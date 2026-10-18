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
	"slices"
	"sort"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// InstallLister is the read side the CatalogScoper needs: what a principal has
// installed on a gateway.
type InstallLister interface {
	ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*installationdomain.Installation, error)
}

// Scoper builds the per-principal surface of the MCP Store: the shared
// registries the calling principal has actively installed, narrowed by the
// access level and grants that apply to them. Every other consumer is left
// untouched — a consumer's servers are the ones an admin bound to it, which is
// the decision itself, so there is nothing per-principal to compute.
//
//go:generate mockery --name=Scoper --dir=. --output=./mocks --filename=store_scoper_mock.go --case=underscore --with-expecter
type Scoper interface {
	Scope(ctx context.Context, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error)
}

type scoper struct {
	installs   InstallLister
	registries RegistryLister
	grants     storeaccessdomain.Reader
	modes      ModeResolver
	// catalog is the embedded MCP catalog. On the data plane a first install
	// writes the installation immediately, but the registry it materialises
	// reaches this process only with the next config snapshot. The catalog is
	// already on every replica, so a just-written install can be served from it
	// until that snapshot arrives. Nil leaves the snapshot as the only source.
	catalog CatalogReader
	now     func() time.Time
	// snapshot reports whether the registry list is a live converge recent
	// enough to bridge. Nil means there is no snapshot (the control plane's
	// database, or a test) and a just-written install may still be served
	// from the catalog.
	snapshot SnapshotStandIn
}

// pendingShelfWindow is how long a just-written install may be served from the
// catalog while its registry is still absent from the config snapshot. The lag
// on dev is a few seconds (recompile debounce plus compile and push). Two
// minutes leaves room for a slow compile and for the installing data plane's
// clock to sit ahead of this replica. Past the window an install whose
// registry is still absent stays dormant, the same as a registry that was
// deleted.
const pendingShelfWindow = 2 * time.Minute

// pendingShelfSkew is how far UpdatedAt may sit in the future and still count
// as just written. The data plane stamps it when it records the install
// (installationForStatus); another replica only reads the row.
const pendingShelfSkew = 30 * time.Second

// SnapshotStandIn reports whether the registry list just read may be bridged
// from the catalog. maxAge is the stand-in window. False when that list is a
// restored last-known-good snapshot or a live one older than maxAge: the
// database may already hold the registry, including one an administrator
// turned off, and a re-install must not bring it back.
type SnapshotStandIn func(maxAge time.Duration) bool

// ScoperOption tunes NewScoper.
type ScoperOption func(*scoper)

// WithScoperModes resolves the principal's Store mode live from the gateway's
// policies instead of the token claim / gateway default alone.
func WithScoperModes(r ModeResolver) ScoperOption {
	return func(s *scoper) { s.modes = r }
}

// WithScoperCatalog lets a just-installed server be served from the embedded
// catalog until the config snapshot carries the registry the install
// materialised. Without it the snapshot is the only registry source.
func WithScoperCatalog(r CatalogReader) ScoperOption {
	return func(s *scoper) { s.catalog = r }
}

// WithScoperSnapshot stops the stand-in when the registry list is stale or
// restored from last-known-good. Without it the list is treated as current.
func WithScoperSnapshot(allow SnapshotStandIn) ScoperOption {
	return func(s *scoper) {
		if allow != nil {
			s.snapshot = allow
		}
	}
}

// withScoperClock overrides the clock the pending-shelf window is measured
// against. Tests use it; production leaves the wall clock.
func withScoperClock(now func() time.Time) ScoperOption {
	return func(s *scoper) {
		if now != nil {
			s.now = now
		}
	}
}

// NewScoper wires the CatalogScoper over the installation store, the gateway
// registry list and the Store access grants. grants may be nil on a plane
// without them, which fails closed under Selected access (no install is
// exposed) and is irrelevant under All.
func NewScoper(installs InstallLister, registries RegistryLister, grants storeaccessdomain.Reader, opts ...ScoperOption) (Scoper, error) {
	if installs == nil || registries == nil {
		return nil, ErrUnavailable
	}
	s := &scoper{installs: installs, registries: registries, grants: grants, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

func (s *scoper) Scope(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
) (*appconsumer.RoutableConsumer, error) {
	if rc == nil || rc.Consumer == nil {
		return rc, nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return rc, nil
	}
	// Only the Store is governed by Access. A custom consumer's surface is the
	// set of servers an admin bound to it, the same for every caller it admits:
	// the consumer *is* the decision. Access exists for the self-service catalog,
	// where the person picks and there is no per-application configuration to
	// read — applying it to a consumer as well would put two places in charge of
	// one surface, and let an admin bind a server its own users cannot see.
	if !consumerdomain.IsStoreConsumer(rc.Consumer) {
		return rc, nil
	}

	installs, err := s.installs.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil, fmt.Errorf("store scoper: list installations: %w", err)
	}
	active := make([]*installationdomain.Installation, 0, len(installs))
	for _, in := range installs {
		if in.IsActive() {
			active = append(active, in)
		}
	}
	if len(active) == 0 {
		return rc, nil
	}
	// Stable exposure order: by code, then install age, then id.
	sort.Slice(active, func(i, j int) bool {
		if active[i].CatalogCode != active[j].CatalogCode {
			return active[i].CatalogCode < active[j].CatalogCode
		}
		if !active[i].CreatedAt.Equal(active[j].CreatedAt) {
			return active[i].CreatedAt.Before(active[j].CreatedAt)
		}
		return active[i].ID.String() < active[j].ID.String()
	})

	regs, err := s.installedRegistries(ctx, rc.Consumer.GatewayID, principal, active)
	if err != nil {
		return nil, err
	}

	// Copy so the shared synthetic Store consumer is never mutated across
	// concurrent principals.
	scoped := *rc
	scoped.Registries = regs
	return &scoped, nil
}

// installedRegistries maps a principal's active installs onto the gateway's
// configured instances (registries). An install bound to a registry exposes
// that registry; an unbound one exposes the code's canonical instance (the
// oldest registry carrying the code). When the snapshot has no instance yet
// and the install was just written, that instance is built from the catalog
// until the snapshot catches up (see fillPendingShelves). A code with a
// single active install exposes the registry under its own id and name; when
// that install carries
// per-user config the exposure is a shallow clone carrying the config as a
// request-scoped overlay (MCPTarget.InstanceConfig) so the dial-time URL
// resolver reads this exact instance's values. A code with several active
// installs (two Snowflake schemas, or two configured instances) exposes one
// per-install clone each: a distinct registry id and a disambiguating label so
// the composer names their tools apart. Installs that reach the same server with
// the same config are one instance, exposed once (see distinctInstalls).
//
// Access is re-checked here, not only at install time: under Selected an
// install stays exposed only while a grant still names the principal for its
// code or its instance, so tightening a grant later revokes access immediately
// rather than only for future installs. An instance an administrator turned off
// is not exposed either, and the install is not moved onto another instance in
// its place: that one may hold a different account.
func (s *scoper) installedRegistries(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principal *identity.Principal,
	active []*installationdomain.Installation,
) ([]*registrydomain.Registry, error) {
	items, err := listRegistriesForInstalls(ctx, s.registries, gatewayID, active)
	if err != nil {
		return nil, fmt.Errorf("store scoper: list registries: %w", err)
	}
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(items))
	byCode := make(map[string][]*registrydomain.Registry)
	for _, reg := range items {
		if reg == nil || reg.MCPTarget == nil {
			continue
		}
		byID[reg.ID] = reg
		code := registrydomain.StoreCode(reg)
		byCode[code] = append(byCode[code], reg)
	}
	s.fillPendingShelves(gatewayID, active, byCode)
	for _, regs := range byCode {
		sortRegistries(regs)
	}
	groups := principal.Groups()
	// Under All every install stands; under Selected an install only stays
	// exposed while a grant still names the principal for its code or instance.
	enforceGrants := ResolveMode(ctx, s.modes, ModeQuery{
		GatewayID: gatewayID,
		Subject:   principal.Subject,
		Groups:    groups,
		Fallback:  EffectiveStoreMode(ctx),
	}) != gatewaydomain.StoreModeOpen
	var grants *storeaccessdomain.Set
	if enforceGrants {
		if grants, err = loadGrantSet(ctx, s.grants, gatewayID); err != nil {
			return nil, fmt.Errorf("store scoper: %w", err)
		}
	}
	exposed, countByCode := distinctInstalls(active, byID, byCode)
	out := make([]*registrydomain.Registry, 0, len(exposed))
	for _, e := range exposed {
		in, shelf := e.install, e.shelf
		// Checked after counting, like a grant: turning an instance off and on
		// again must not rename its siblings' tools.
		if !shelf.Enabled {
			continue
		}
		if enforceGrants && !grants.InstanceAllows(in.CatalogCode, shelf.ID, groups, principal.Subject) {
			continue
		}
		if countByCode[in.CatalogCode] <= 1 {
			if len(in.Config) == 0 {
				out = append(out, registryAtNamingVersion(shelf, in.NamingVersion))
				continue
			}
			out = append(out, stampNamingVersion(configuredRegistry(shelf, in), in.NamingVersion))
			continue
		}
		out = append(out, stampNamingVersion(instanceRegistry(shelf, in), in.NamingVersion))
	}
	return out, nil
}

type installedInstance struct {
	install *installationdomain.Installation
	shelf   *registrydomain.Registry
}

// distinctInstalls pairs each install with the registry that serves it, drops
// every one that reaches the same server with the same config as an earlier one
// in active, and counts what is left per code.
//
// Such installs are one instance recorded twice: an approved request stays bound
// to the server it named, while a later install of the same code binds
// implicitly. Exposed as two per-install clones, they served the same tools
// under the same names, and a client that refuses duplicate names lost all of
// them.
//
// An install whose server is gone is dropped too. Counted, it made its live
// sibling a clone whose tools carry a per-instance name, which changed again
// once the dead row was cleaned up; one bound to a deleted registry never comes
// back, since registry ids are not reused. Grants are applied later, on
// purpose: a sibling's grant can be restored, and the names of the instance
// still exposed must not change each time it is.
func distinctInstalls(
	active []*installationdomain.Installation,
	byID map[ids.RegistryID]*registrydomain.Registry,
	byCode map[string][]*registrydomain.Registry,
) ([]installedInstance, map[string]int) {
	out := make([]installedInstance, 0, len(active))
	countByCode := make(map[string]int, len(active))
	for _, in := range active {
		shelf := resolveInstance(in, byID, byCode)
		if shelf == nil {
			continue
		}
		if slices.ContainsFunc(out, func(e installedInstance) bool {
			return e.shelf.ID == shelf.ID && e.install.SameConfig(in.Config)
		}) {
			continue
		}
		out = append(out, installedInstance{install: in, shelf: shelf})
		countByCode[in.CatalogCode]++
	}
	return out, countByCode
}

// resolveInstance returns the registry an install exposes: the one it is bound
// to (which must still exist and still carry the code — a re-pointed registry
// does not leak another server), else the code's canonical instance. Nil when
// nothing matches (the registry was deleted; the install is dormant).
func resolveInstance(
	in *installationdomain.Installation,
	byID map[ids.RegistryID]*registrydomain.Registry,
	byCode map[string][]*registrydomain.Registry,
) *registrydomain.Registry {
	if !in.RegistryID.IsNil() {
		reg, ok := byID[in.RegistryID]
		if !ok || registrydomain.StoreCode(reg) != in.CatalogCode {
			return nil
		}
		return reg
	}
	if regs := byCode[in.CatalogCode]; len(regs) > 0 {
		return regs[0]
	}
	return nil
}

// fillPendingShelves adds a catalog-shaped registry for an active install whose
// server is not in the snapshot yet. The data plane reads registries from the
// config snapshot, which is compiled and pushed after the control plane
// persists the registry a first install materialises. The installation row and
// the embedded catalog are already on every replica, so the next tools/list —
// whichever pod takes it — can dial the server the install just recorded.
//
// Only an unbound install qualifies. A binding names one registry id, and a
// missing id stays dormant rather than being replaced by another instance.
// A snapshot entry for the code, including one an administrator turned off,
// is left alone. The stand-in is the same shape Ensure persists (URL,
// transport, auth). Its id is the installation's, so every replica agrees and
// audit's registry id joins the call to that row; a later snapshot registry
// replaces it once instead of sitting beside it. A server that is not
// self-service is skipped: its credential lives on the admin's registry, which
// the catalog does not carry. A registry read that failed never reaches here.
func (s *scoper) fillPendingShelves(
	gatewayID ids.GatewayID,
	active []*installationdomain.Installation,
	byCode map[string][]*registrydomain.Registry,
) {
	if s == nil || s.catalog == nil {
		return
	}
	// A stale or last-known-good snapshot is missing registries the database
	// already has. Serving the catalog then would override a later disable.
	// Only a live snapshot younger than the window is the first-install lag.
	if s.snapshot != nil && !s.snapshot(pendingShelfWindow) {
		return
	}
	now := s.clock()
	filled := make(map[string]struct{}, len(active))
	for _, in := range active {
		if in == nil || !in.RegistryID.IsNil() || in.CatalogCode == "" {
			continue
		}
		if _, ok := filled[in.CatalogCode]; ok {
			continue
		}
		if len(byCode[in.CatalogCode]) > 0 || !pendingShelfFresh(now, in.UpdatedAt) {
			continue
		}
		entry, ok := s.catalog.GetByCode(in.CatalogCode)
		if !ok || catalogNeedsAdminCredential(entry) {
			continue
		}
		reg, err := catalogRegistry(entry, gatewayID)
		if err != nil {
			continue
		}
		// The id audit already stores is the registry id. Using the install's
		// id there joins the call to this row, and the catalog code joins that
		// row to the real registry once the snapshot arrives. Origin marks the
		// stand-in; it is not persisted.
		reg.ID = ids.From[ids.RegistryKind](in.ID.UUID())
		if reg.MCPTarget != nil {
			reg.MCPTarget.Origin = registrydomain.MCPOriginPending
		}
		// Pin the timestamps to the install so discovery caches one entry for
		// the window instead of a new one on every list.
		reg.CreatedAt = in.UpdatedAt
		reg.UpdatedAt = in.UpdatedAt
		byCode[in.CatalogCode] = []*registrydomain.Registry{reg}
		filled[in.CatalogCode] = struct{}{}
	}
}

func (s *scoper) clock() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func pendingShelfFresh(now, updated time.Time) bool {
	if updated.IsZero() {
		return false
	}
	if updated.After(now.Add(pendingShelfSkew)) {
		return false
	}
	return !updated.Before(now.Add(-pendingShelfWindow))
}

// registryAtNamingVersion returns shelf when it already carries version. A
// different version is stamped on a shallow copy: shelf is the shared snapshot
// registry, and writing a principal's version onto it would rename every other
// principal's tools.
func registryAtNamingVersion(shelf *registrydomain.Registry, version int) *registrydomain.Registry {
	if shelf == nil || registryNamingVersion(shelf) == version {
		return shelf
	}
	clone := *shelf
	if shelf.MCPTarget == nil {
		return &clone
	}
	target := *shelf.MCPTarget
	target.NamingVersion = version
	clone.MCPTarget = &target
	return &clone
}

func registryNamingVersion(reg *registrydomain.Registry) int {
	if reg == nil || reg.MCPTarget == nil {
		return 0
	}
	return reg.MCPTarget.NamingVersion
}

// stampNamingVersion records the install's naming rules on a registry clone.
// The clone already owns its target; the shared shelf is not modified.
func stampNamingVersion(reg *registrydomain.Registry, version int) *registrydomain.Registry {
	if reg == nil || reg.MCPTarget == nil || reg.MCPTarget.NamingVersion == version {
		return reg
	}
	target := *reg.MCPTarget
	target.NamingVersion = version
	reg.MCPTarget = &target
	return reg
}

// configuredRegistry is the single-instance exposure of an install that carries
// per-user config: a shallow clone of the shelf registry (same id, same name — no
// relabel, since there is nothing to disambiguate) whose target carries the
// install's config as the dial-time overlay and whose InstanceOf points back at
// the shelf. The shared shelf entry is never mutated.
func configuredRegistry(
	shelf *registrydomain.Registry,
	in *installationdomain.Installation,
) *registrydomain.Registry {
	clone := *shelf
	target := *shelf.MCPTarget
	target.InstanceConfig = copyConfig(in.Config)
	clone.MCPTarget = &target
	clone.InstanceOf = shelf.ID
	return &clone
}

func copyConfig(config map[string]string) map[string]string {
	if len(config) == 0 {
		return nil
	}
	cfg := make(map[string]string, len(config))
	for k, v := range config {
		cfg[k] = v
	}
	return cfg
}

// instanceRegistry clones a shelf registry into a per-instance view for one
// install: a stable per-instance id (re-tagged from the install id), InstanceOf
// pointing back at the shelf so policy scopes naming the shelf reach every
// instance, a label suffixed with the install's distinguishing config, and that
// config as a request-scoped overlay the dial-time resolver reads. It copies the
// registry and its target so the shared shelf entry is never mutated.
func instanceRegistry(
	shelf *registrydomain.Registry,
	in *installationdomain.Installation,
) *registrydomain.Registry {
	clone := *shelf
	target := *shelf.MCPTarget
	clone.MCPTarget = &target
	clone.ID = ids.From[ids.RegistryKind](in.ID.UUID())
	clone.InstanceOf = shelf.ID
	if label := in.InstanceLabel(); label != "" {
		clone.Name = instanceName(shelf, label)
	}
	target.InstanceConfig = copyConfig(in.Config)
	return &clone
}

func instanceName(shelf *registrydomain.Registry, label string) string {
	base := strings.TrimSpace(shelf.Name)
	if base == "" && shelf.MCPTarget != nil {
		base = shelf.MCPTarget.Code
	}
	if base == "" {
		return label
	}
	return base + " (" + label + ")"
}
