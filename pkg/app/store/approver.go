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

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ErrNotShelved is returned when an admin approves a request for a server that
// has no shelf registry yet. Approving cannot conjure the upstream connection —
// the admin connects (shelves) the server first, then approves. It maps to 409.
var ErrNotShelved = fmt.Errorf("store: server is not on the shelf; connect it first: %w", commonerrors.ErrConflict)

// RegistryShelf is the registry access the approver needs: find the shelf
// registry for a catalog code and mark it available when approving.
type RegistryShelf interface {
	List(ctx context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error)
	Update(ctx context.Context, b *registrydomain.Registry) error
}

// PendingRequest is one row in the admin approval queue.
type PendingRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	Name         string
	InstalledBy  string
	RequestedAt  time.Time
}

// ApproveRequest / DenyRequest identify the install request to decide, plus the
// admin acting on it (for audit).
type ApproveRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	ApprovedBy   string
}

type DenyRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	DeniedBy     string
}

//go:generate mockery --name=Approver --dir=. --output=./mocks --filename=store_approver_mock.go --case=underscore --with-expecter
type Approver interface {
	// ListPending returns the gateway's pending install requests, oldest first.
	ListPending(ctx context.Context, gatewayID ids.GatewayID) ([]PendingRequest, error)
	// Approve shelves the server available (if not already) and marks the
	// request installed. ErrNotShelved when no registry exists for the code.
	Approve(ctx context.Context, in ApproveRequest) error
	// Deny marks the request revoked, keeping the row for audit.
	Deny(ctx context.Context, in DenyRequest) error
}

var _ Approver = (*approver)(nil)

type approver struct {
	catalog    CatalogReader
	registries RegistryShelf
	installs   installationdomain.Repository
}

// NewApprover wires the Store approval service.
func NewApprover(
	catalog CatalogReader,
	registries RegistryShelf,
	installs installationdomain.Repository,
) (Approver, error) {
	if catalog == nil || registries == nil || installs == nil {
		return nil, ErrUnavailable
	}
	return &approver{catalog: catalog, registries: registries, installs: installs}, nil
}

func (a *approver) ListPending(ctx context.Context, gatewayID ids.GatewayID) ([]PendingRequest, error) {
	rows, err := a.installs.ListPendingByGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	out := make([]PendingRequest, 0, len(rows))
	for _, in := range rows {
		if in == nil {
			continue
		}
		name := in.CatalogCode
		if entry, ok := a.catalog.GetByCode(in.CatalogCode); ok {
			name = displayName(entry, in.CatalogCode)
		}
		out = append(out, PendingRequest{
			GatewayID:    in.GatewayID,
			PrincipalSub: in.PrincipalSub,
			Code:         in.CatalogCode,
			Name:         name,
			InstalledBy:  in.InstalledBy,
			RequestedAt:  in.CreatedAt,
		})
	}
	return out, nil
}

func (a *approver) Approve(ctx context.Context, in ApproveRequest) error {
	code := strings.TrimSpace(in.Code)
	existing, err := a.installs.Find(ctx, in.GatewayID, in.PrincipalSub, code)
	if err != nil {
		return err
	}
	if existing.Status == installationdomain.StatusInstalled {
		return nil // already approved — idempotent
	}

	reg, err := findRegistryByCode(ctx, a.registries, in.GatewayID, code)
	if err != nil {
		return err
	}
	if reg == nil || reg.MCPTarget == nil {
		return fmt.Errorf("%w: %q", ErrNotShelved, code)
	}
	// Approving a request shelves the server available. The requires-approval
	// gate is left untouched so future installs still queue.
	if !reg.MCPTarget.StoreAvailable() {
		reg.MCPTarget.Store = ensureStoreAvailable(reg.MCPTarget.Store)
		if err := a.registries.Update(ctx, reg); err != nil {
			return fmt.Errorf("store: shelve registry: %w", err)
		}
	}

	existing.Status = installationdomain.StatusInstalled
	existing.UpdatedAt = time.Now().UTC()
	return a.installs.Upsert(ctx, existing)
}

func (a *approver) Deny(ctx context.Context, in DenyRequest) error {
	existing, err := a.installs.Find(ctx, in.GatewayID, in.PrincipalSub, strings.TrimSpace(in.Code))
	if err != nil {
		return err
	}
	if existing.Status == installationdomain.StatusRevoked {
		return nil // already denied — idempotent
	}
	existing.Status = installationdomain.StatusRevoked
	existing.UpdatedAt = time.Now().UTC()
	return a.installs.Upsert(ctx, existing)
}

// ensureStoreAvailable returns a store config with Available set, preserving any
// existing approval/role governance.
func ensureStoreAvailable(store *registrydomain.MCPStoreConfig) *registrydomain.MCPStoreConfig {
	if store == nil {
		return &registrydomain.MCPStoreConfig{Available: true}
	}
	store.Available = true
	return store
}
