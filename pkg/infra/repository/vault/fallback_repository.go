// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// fallbackRepository reads a second vault whenever the primary holds nothing.
//
// It exists because a deployed gateway has two credential stores. The control
// plane owns Postgres, while the DB-less MCP data plane
// (CONFIG_SYNC_DATA_PLANE_ENABLED) keeps per-user upstream credentials in the
// shared Redis vault — and the connect flow, which is what writes them, runs
// there. So every account a person links from their MCP client lands in Redis
// and is invisible to a control-plane read (the Portal's per-user connection
// state, the account shown on a consumer) unless that read looks in Redis too.
//
// Writes stay on the primary, so a credential the control plane stores itself
// is durable. A delete removes the credential from both stores: revoking from
// the control plane must never leave a live copy behind on the data plane.
type fallbackRepository struct {
	primary  domain.Repository
	fallback domain.Repository
}

// NewFallbackRepository composes two vaults into one read path. Passing a nil
// fallback returns the primary unchanged, so a deployment with a single store
// carries no wrapper.
func NewFallbackRepository(primary, fallback domain.Repository) domain.Repository {
	if primary == nil {
		return fallback
	}
	if fallback == nil {
		return primary
	}
	return &fallbackRepository{primary: primary, fallback: fallback}
}

func (r *fallbackRepository) Upsert(ctx context.Context, c *domain.Credential) error {
	return r.primary.Upsert(ctx, c)
}

func (r *fallbackRepository) Find(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, provider string,
) (*domain.Credential, error) {
	cred, err := r.primary.Find(ctx, gatewayID, principalSub, provider)
	if !errors.Is(err, domain.ErrNotFound) {
		// Anything else is the primary's answer, ErrUndecryptable included: a
		// credential written under a rotated key is still an answer about that
		// person, and hiding it behind the other store would report them as
		// never connected.
		return cred, err
	}
	return r.fallback.Find(ctx, gatewayID, principalSub, provider)
}

func (r *fallbackRepository) ListByPrincipal(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
) ([]*domain.Credential, error) {
	primary, err := r.primary.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return nil, err
	}
	fallback, err := r.fallback.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(primary))
	out := make([]*domain.Credential, 0, len(primary)+len(fallback))
	for _, cred := range primary {
		if cred == nil {
			continue
		}
		seen[cred.Provider] = struct{}{}
		out = append(out, cred)
	}
	for _, cred := range fallback {
		if cred == nil {
			continue
		}
		if _, ok := seen[cred.Provider]; ok {
			continue
		}
		out = append(out, cred)
	}
	return out, nil
}

func (r *fallbackRepository) Delete(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, provider string,
) error {
	primaryErr := r.primary.Delete(ctx, gatewayID, principalSub, provider)
	fallbackErr := r.fallback.Delete(ctx, gatewayID, principalSub, provider)
	// Missing in one store is not a failure — the credential only ever lived in
	// the other one. Missing in both is the caller's ErrNotFound.
	switch {
	case primaryErr != nil && !errors.Is(primaryErr, domain.ErrNotFound):
		return primaryErr
	case fallbackErr != nil && !errors.Is(fallbackErr, domain.ErrNotFound):
		return fallbackErr
	case primaryErr != nil && fallbackErr != nil:
		return primaryErr
	default:
		return nil
	}
}
