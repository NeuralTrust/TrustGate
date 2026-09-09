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
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
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

// GrantStore is the grant access the approver needs: read a gateway's grants
// and write the one an approval extends.
type GrantStore interface {
	storeaccessdomain.Reader
	Upsert(ctx context.Context, g *storeaccessdomain.Grant) error
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
	// Reason is why the requester wants it, in their own words. Empty for a
	// request filed by a client that sent none.
	Reason      string
	RequestedAt time.Time
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
	// GrantToGroup, when set, grants the server to this group key (one of the
	// requester's groups) instead of to the requester alone — the "Grant access
	// to" choice on approve. The requester is covered through their membership.
	GrantToGroup string
}

// DecidedRequest is one row of the approval history: a request an admin
// approved or denied.
type DecidedRequest struct {
	GatewayID    ids.GatewayID
	InstanceID   string
	PrincipalSub string
	Code         string
	Name         string
	RegistryID   ids.RegistryID
	// Reason is what the requester wrote when they asked; a decided request
	// keeps it, so the history says what was approved or denied and why it was
	// asked for.
	Reason      string
	Decision    installationdomain.Decision
	DecidedBy   string
	DecidedAt   time.Time
	RequestedAt time.Time
}

// ErrHistoryUnavailable: this plane has no durable decision history to read.
var ErrHistoryUnavailable = fmt.Errorf("store: approval history unavailable: %w", commonerrors.ErrNotFound)

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
	// Approve grants the requester — or the group named by GrantToGroup — the
	// server: its code, or, when the code has several configured instances, the
	// one the request is bound to. It materialises the registry when none exists
	// yet and marks the request installed. ErrNotShelved when the server cannot
	// be materialised here and no registry exists for the code.
	Approve(ctx context.Context, in ApproveRequest) error
	// Deny marks the request revoked, keeping the row for audit.
	Deny(ctx context.Context, in DenyRequest) error
	// ListDecided returns the requests already approved or denied on a gateway,
	// newest decision first. ErrHistoryUnavailable without a durable store.
	ListDecided(ctx context.Context, gatewayID ids.GatewayID) ([]DecidedRequest, error)
}

var _ Approver = (*approver)(nil)

type approver struct {
	catalog    CatalogReader
	registries RegistryLister
	installs   installationdomain.Repository
	grants     GrantStore
	ensurer    RegistryEnsurer
	history    installationdomain.DecisionHistory
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

// WithApproverHistory lets ListDecided read the decided requests (the durable
// installation store implements it; data-plane proxies do not).
func WithApproverHistory(h installationdomain.DecisionHistory) ApproverOption {
	return func(a *approver) { a.history = h }
}

// NewApprover wires the Store approval service. grants is where an approval
// lands: approving adds the requester to the grant on the requested code (or
// instance), so their next install is instant and the Access page shows it.
func NewApprover(
	catalog CatalogReader,
	registries RegistryLister,
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
			Reason:       in.Reason,
			RequestedAt:  in.CreatedAt,
		})
	}
	return out, nil
}

const decidedHistoryLimit = 200

func (a *approver) ListDecided(ctx context.Context, gatewayID ids.GatewayID) ([]DecidedRequest, error) {
	if a.history == nil {
		return nil, ErrHistoryUnavailable
	}
	rows, err := a.history.ListDecidedByGateway(ctx, gatewayID, decidedHistoryLimit)
	if err != nil {
		return nil, fmt.Errorf("store: list decided requests: %w", err)
	}
	out := make([]DecidedRequest, 0, len(rows))
	for _, in := range rows {
		if in == nil || in.Decision == "" {
			continue
		}
		name := in.CatalogCode
		if entry, ok := a.catalog.GetByCode(in.CatalogCode); ok {
			name = displayName(entry, in.CatalogCode)
		}
		out = append(out, DecidedRequest{
			GatewayID:    in.GatewayID,
			InstanceID:   in.ID.String(),
			PrincipalSub: in.PrincipalSub,
			Code:         in.CatalogCode,
			Name:         name,
			RegistryID:   in.RegistryID,
			Reason:       in.Reason,
			Decision:     in.Decision,
			DecidedBy:    in.DecidedBy,
			DecidedAt:    in.DecidedAt,
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
	// Approving a request GRANTS the resource to the requester — or to the group
	// the admin chose — so their next install is instant and the Access page
	// reflects it. Grants are the only governance there is.
	//
	// A server with one configured instance is granted as the server: that is
	// what "grant this server" means to the admin who reads it back (Access
	// shows a single-instance server as one row, and grants it at code level
	// itself), and a code grant survives the instance being re-materialised
	// instead of being orphaned by a stale id. The Portal binds its request to
	// the sole instance so a *later* approval lands on the right one, which is
	// not the same thing as pinning the grant there. With several instances the
	// binding is a real choice and is kept.
	grantRegistryID := existing.RegistryID
	if len(instances) <= 1 {
		grantRegistryID = ids.RegistryID{}
	}
	if err := a.grantRequester(ctx, in.GatewayID, code, grantRegistryID, existing.PrincipalSub, in.GrantToGroup); err != nil {
		return err
	}

	existing.Decide(installationdomain.DecisionApproved, in.ApprovedBy, time.Now().UTC())
	return a.installs.Upsert(ctx, existing)
}

// grantRequester adds the principal — or, when the admin chose a group, that
// group — to the grant the request asked for, unless the grant already covers
// them (the code-level grant, or the instance's own).
func (a *approver) grantRequester(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
	registryID ids.RegistryID,
	subject string,
	group string,
) error {
	grants, err := loadGrantSet(ctx, a.grants, gatewayID)
	if err != nil {
		return err
	}
	group = strings.TrimSpace(group)
	if group != "" {
		if grants.InstanceAllows(code, registryID, []string{group}, "") {
			return nil
		}
	} else if grants.InstanceAllows(code, registryID, nil, subject) {
		return nil
	}
	var grant *storeaccessdomain.Grant
	if registryID.IsNil() {
		grant = grants.Code(code)
	} else {
		grant = grants.Instance(registryID)
	}
	if grant == nil {
		if grant, err = storeaccessdomain.New(gatewayID, code, registryID, nil, nil); err != nil {
			return err
		}
	} else {
		copied := *grant
		grant = &copied
	}
	if group != "" {
		grant.AddGroup(group)
	} else {
		grant.AddUser(subject)
	}
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
	existing.Decide(installationdomain.DecisionDenied, in.DeniedBy, time.Now().UTC())
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
