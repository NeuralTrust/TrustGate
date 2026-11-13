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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// CredentialSummary is a stored credential without its secrets: who holds it,
// under which provider key, and when it was written or refused.
type CredentialSummary struct {
	PrincipalSub string
	Provider     string
	// ExpiresAt is zero for a credential that does not expire. For a value
	// with no expiry of its own, a past ExpiresAt is the refusal mark.
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ProviderPrefixStore lists and removes credentials of every principal whose
// provider key starts with a prefix: the values every person holds for one
// registry instance, for an admin roster or reset.
type ProviderPrefixStore interface {
	ListByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) ([]CredentialSummary, error)
	// DeleteByProviderPrefix removes them and reports how many it removed.
	DeleteByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) (int, error)
}

// ReplicatedUpserter is a store that can write a credential everywhere it is
// read from. A control-plane write meant for the MCP data plane uses it: the
// control plane writes to Postgres, and the data plane reads the shared Redis
// vault only.
type ReplicatedUpserter interface {
	UpsertReplicated(ctx context.Context, c *Credential) error
}
