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
	storegrantdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storegrant"
)

// ErrNotShelved is returned when an admin approves a request for a server that
// has no shelf registry yet. Approving cannot conjure the upstream connection —
// the admin connects (shelves) the server first, then approves. It maps to 409.
var ErrNotShelved = fmt.Errorf("store: server is not on the shelf; connect it first: %w", commonerrors.ErrConflict)

// ErrAmbiguousRequest is returned when an approve/deny names only a catalog code
// and the principal holds several live (installed or pending) instances of it,
// so the decision cannot be applied to one without guessing. The caller must
// pass the instance id (from the pending queue). It maps to 409.
var ErrAmbiguousRequest = fmt.Errorf("store: several instances match; pass instance_id: %w", commonerrors.ErrConflict)

// RegistryShelf is the registry access the approver needs: the gateway's
// configured instances, to resolve which one a request lands on.
type RegistryShelf interface {
	List(ctx context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error)
}

// GrantStore is the grant access the approver needs: read a gateway's grants
// and write the one an approval extends.
type GrantStore interface {
	storegrantdomain.Reader
	Upsert(ctx context.Context, g *storegrantdomain.Grant) error
}

// PendingRequest is one row in the admin approval queue.
type PendingRequest struct {
	GatewayID ids.GatewayID
	// InstanceID identifies the exact installation row awaiting a decision; the
	// admin passes it back on approve/deny so the decision lands on this instance
	// even when the principal holds others of the same code.
	InstanceID   string
	PrincipalSub string
	Code         string
	Name         string
	InstalledBy  string
	RequestedAt  time.Time
}

// ApproveRequest / DenyRequest identify the install request to decide, plus the
// admin acting on it (for audit). InstanceID targets one exact instance; when
// empty, Code is used only if the principal holds exactly one live instance of
// it (backward compatible with single-instance callers).
type ApproveRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	InstanceID   string
	ApprovedBy   string
}

type DenyRequest struct {
	GatewayID    ids.GatewayID
	PrincipalSub string
	Code         string
	InstanceID   string
	DeniedBy     string
}

//go:generate mockery --name=Approver --dir=. --output=./mocks --filename=store_approver_mock.go --case=underscore --with-expecter
type Approver interface {
	// ListPending returns the gateway's pending install requests, oldest first.
	ListPending(ctx context.Context, gatewayID ids.GatewayID) ([]PendingRequest, error)
	// Approve grants the requester the server (its code, or the one instance the
	// request is bound to), materialising the registry when none exists yet, and
	// marks the request installed. ErrNotShelved when the server cannot be
	// materialised here and no registry exists for the code.
	Approve(ctx context.Context, in ApproveRequest) error
	// Deny marks the request revoked, keeping the row for audit.
	Deny(ctx context.Context, in DenyRequest) error
}

var _ Approver = (*approver)(nil)

type approver struct {
	catalog    CatalogReader
	registries RegistryShelf
	installs   installationdomain.Repository
	grants     GrantStore
	ensurer    RegistryEnsurer
}

// ApproverOption tunes NewApprover.
type ApproverOption func(*approver)

// WithApproverEnsurer lets Approve materialise the shelf registry for a request
// whose server was never connected (a Selected principal asked for a catalog
// server nobody shelved yet). Without it such an approve returns ErrNotShelved
// and the admin must connect the server first.
func WithApproverEnsurer(e RegistryEnsurer) ApproverOption {
	return func(a *approver) { a.ensurer = e }
}

// NewApprover wires the Store approval service. grants is where an approval
// lands: approving adds the requester to the grant on the requested code (or
// instance), so their next install is instant and the Access page shows it.
func NewApprover(
	catalog CatalogReader,
	registries RegistryShelf,
	installs installationdomain.Repository,
	grants GrantStore,
	opts ...ApproverOption,
) (Approver, error) {
	if catalog == nil || registries == nil || installs == nil || grants == nil {
		return nil, ErrUnavailable
	}
	a := &approver{catalog: catalog, registries: registries, installs: installs, grants: grants}
	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}
	return a, nil
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
			InstanceID:   in.ID.String(),
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
	existing, err := a.target(ctx, in.GatewayID, in.PrincipalSub, in.Code, in.InstanceID)
	if err != nil {
		return err
	}
	if existing.Status == installationdomain.StatusInstalled {
		return nil // already approved — idempotent
	}
	// A denied (revoked) request is not silently resurrected by a by-code approve;
	// re-granting one is an explicit, instance-addressed decision.
	if existing.Status == installationdomain.StatusRevoked && strings.TrimSpace(in.InstanceID) == "" {
		return fmt.Errorf("%w: no pending request for %q", installationdomain.ErrNotFound, existing.CatalogCode)
	}
	code := existing.CatalogCode

	instances, err := findRegistriesByCode(ctx, a.registries, in.GatewayID, code)
	if err != nil {
		return err
	}
	// A request bound to one configured instance is approved for that instance
	// only; the instance must still exist and still carry the code.
	if !existing.RegistryID.IsNil() && pickRegistry(instances, existing.RegistryID) == nil {
		return fmt.Errorf("%w: instance %s of %q", ErrNotShelved, existing.RegistryID, code)
	}
	if len(instances) == 0 {
		// Nobody connected this server yet: materialise it so the install has a
		// registry to land on, when we can.
		if a.ensurer == nil {
			return fmt.Errorf("%w: %q", ErrNotShelved, code)
		}
		if err := a.ensurer.Ensure(ctx, in.GatewayID, code); err != nil {
			return fmt.Errorf("store: materialise registry: %w", err)
		}
	}
	// Approving a request GRANTS the resource to the requester: their subject is
	// added to the grant on the requested code (or, for a request bound to one
	// instance, on that instance) so their next install is instant and the
	// Access page reflects it. Grants are the only governance there is.
	if err := a.grantRequester(ctx, in.GatewayID, code, existing.RegistryID, existing.PrincipalSub); err != nil {
		return err
	}

	existing.Status = installationdomain.StatusInstalled
	existing.UpdatedAt = time.Now().UTC()
	return a.installs.Upsert(ctx, existing)
}

// grantRequester adds the principal to the grant the request asked for, unless
// a grant already covers them (the code-level grant, or the instance's own).
func (a *approver) grantRequester(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
	registryID ids.RegistryID,
	subject string,
) error {
	grants, err := loadGrantSet(ctx, a.grants, gatewayID)
	if err != nil {
		return err
	}
	if grants.InstanceAllows(code, registryID, nil, subject) {
		return nil
	}
	var grant *storegrantdomain.Grant
	if registryID.IsNil() {
		grant = grants.Code(code)
	} else {
		grant = grants.Instance(registryID)
	}
	if grant == nil {
		if grant, err = storegrantdomain.New(gatewayID, code, registryID, nil, nil); err != nil {
			return err
		}
	} else {
		copied := *grant
		grant = &copied
	}
	grant.AddUser(subject)
	if err := a.grants.Upsert(ctx, grant); err != nil {
		return fmt.Errorf("store: grant requester: %w", err)
	}
	return nil
}

func (a *approver) Deny(ctx context.Context, in DenyRequest) error {
	existing, err := a.target(ctx, in.GatewayID, in.PrincipalSub, in.Code, in.InstanceID)
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

// target resolves the one installation row a decision applies to. An explicit
// instance id wins (and must belong to the principal, and to code when one is
// given). Without it, the code alone identifies the row only when the principal
// holds exactly one live (installed or pending) instance of it: with several, a
// by-code lookup would silently land on the wrong instance (e.g. deny revoking an
// installed instance instead of the pending one), so it is refused instead.
func (a *approver) target(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, code, instanceID string,
) (*installationdomain.Installation, error) {
	code = strings.TrimSpace(code)
	if id := strings.TrimSpace(instanceID); id != "" {
		installID, err := ids.Parse[ids.InstallationKind](id)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid instance id %q", installationdomain.ErrInvalidInstallation, id)
		}
		row, err := a.installs.FindByID(ctx, gatewayID, principalSub, installID)
		if err != nil {
			return nil, err
		}
		if code != "" && row.CatalogCode != code {
			return nil, fmt.Errorf("%w: instance %q is not an instance of %q", installationdomain.ErrNotFound, id, code)
		}
		return row, nil
	}
	if code == "" {
		return nil, fmt.Errorf("%w: code or instance id is required", installationdomain.ErrInvalidInstallation)
	}
	rows, err := a.installs.ListByPrincipalAndCode(ctx, gatewayID, principalSub, code)
	if err != nil {
		return nil, err
	}
	live := make([]*installationdomain.Installation, 0, len(rows))
	for _, r := range rows {
		if r != nil && r.Status != installationdomain.StatusRevoked {
			live = append(live, r)
		}
	}
	switch len(live) {
	case 1:
		return live[0], nil
	case 0:
		if len(rows) > 0 {
			// Only revoked rows remain: hand back the newest so the caller's
			// idempotency check (deny of an already-denied request) holds.
			return rows[len(rows)-1], nil
		}
		return nil, installationdomain.ErrNotFound
	default:
		return nil, fmt.Errorf("%w: %d live instances of %q", ErrAmbiguousRequest, len(live), code)
	}
}
