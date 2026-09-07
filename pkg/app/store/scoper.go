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
	"sort"
	"strings"

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
// registries the calling principal has actively installed. It leaves any other
// (real) consumer untouched.
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
}

// ScoperOption tunes NewScoper.
type ScoperOption func(*scoper)

// WithScoperModes resolves the principal's Store mode live from the gateway's
// policies instead of the token claim / gateway default alone.
func WithScoperModes(r ModeResolver) ScoperOption {
	return func(s *scoper) { s.modes = r }
}

// NewScoper wires the CatalogScoper over the installation store, the gateway
// registry list and the Store access grants. grants may be nil on a plane
// without them, which fails closed under Selected access (no install is
// exposed) and is irrelevant under All.
func NewScoper(installs InstallLister, registries RegistryLister, grants storeaccessdomain.Reader, opts ...ScoperOption) (Scoper, error) {
	if installs == nil || registries == nil {
		return nil, ErrUnavailable
	}
	s := &scoper{installs: installs, registries: registries, grants: grants}
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
	if rc == nil || rc.Consumer == nil || !consumerdomain.IsStoreConsumer(rc.Consumer) {
		return rc, nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return rc, nil
	}

	installs, err := s.installs.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil, fmt.Errorf("store scoper: list installations: %w", err)
	}
	active := make([]*installationdomain.Installation, 0, len(installs))
	countByCode := make(map[string]int)
	for _, in := range installs {
		if in.IsActive() {
			active = append(active, in)
			countByCode[in.CatalogCode]++
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

	regs, err := s.installedRegistries(ctx, rc.Consumer.GatewayID, principal, active, countByCode)
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
// oldest registry carrying the code). A code with a single active install
// exposes the registry under its own id and name; when that install carries
// per-user config the exposure is a shallow clone carrying the config as a
// request-scoped overlay (MCPTarget.InstanceConfig) so the dial-time URL
// resolver reads this exact instance's values. A code with several active
// installs (two Snowflake schemas, or two configured instances) exposes one
// per-install clone each: a distinct registry id and a disambiguating label so
// the composer names their tools apart.
//
// Access is re-checked here, not only at install time: under Selected an
// install stays exposed only while a grant still names the principal for its
// code or its instance, so tightening a grant later revokes access immediately
// rather than only for future installs.
func (s *scoper) installedRegistries(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principal *identity.Principal,
	active []*installationdomain.Installation,
	countByCode map[string]int,
) ([]*registrydomain.Registry, error) {
	items, _, err := s.registries.List(ctx, registrydomain.ListFilter{
		GatewayID: gatewayID,
		Page:      1,
		Size:      registryListPageSize,
	})
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
		byCode[reg.MCPTarget.Code] = append(byCode[reg.MCPTarget.Code], reg)
	}
	for _, regs := range byCode {
		sortRegistries(regs)
	}
	groups := principalGroups(principal)
	// Under All every install stands; under Selected an install only stays
	// exposed while a grant still names the principal for its code or instance.
	enforceGrants := resolveMode(ctx, s.modes, gatewayID) != gatewaydomain.StoreModeOpen
	var grants *storeaccessdomain.Set
	if enforceGrants {
		if grants, err = loadGrantSet(ctx, s.grants, gatewayID); err != nil {
			return nil, fmt.Errorf("store scoper: %w", err)
		}
	}
	out := make([]*registrydomain.Registry, 0, len(active))
	for _, in := range active {
		shelf := resolveInstance(in, byID, byCode)
		if shelf == nil {
			continue
		}
		if enforceGrants && !grants.InstanceAllows(in.CatalogCode, shelf.ID, groups, principal.Subject) {
			continue
		}
		if countByCode[in.CatalogCode] <= 1 {
			if len(in.Config) == 0 {
				out = append(out, shelf)
				continue
			}
			out = append(out, configuredRegistry(shelf, in))
			continue
		}
		out = append(out, instanceRegistry(shelf, in))
	}
	return out, nil
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
		if !ok || reg.MCPTarget == nil || reg.MCPTarget.Code != in.CatalogCode {
			return nil
		}
		return reg
	}
	if regs := byCode[in.CatalogCode]; len(regs) > 0 {
		return regs[0]
	}
	return nil
}

// principalGroups reads the principal's IdP group memberships from its claims
// (a []string or a JSON-decoded []any), or nil when absent.
func principalGroups(principal *identity.Principal) []string {
	if principal == nil || principal.Claims == nil {
		return nil
	}
	switch v := principal.Claims[identity.ClaimGroups].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// configuredRegistry is the single-instance exposure of an install that carries
// per-user config: a shallow clone of the shelf registry (same id, same name — no
// relabel, since there is nothing to disambiguate) whose target carries the
// install's config as the dial-time overlay. The shared shelf entry is never
// mutated.
func configuredRegistry(
	shelf *registrydomain.Registry,
	in *installationdomain.Installation,
) *registrydomain.Registry {
	clone := *shelf
	target := *shelf.MCPTarget
	target.InstanceConfig = copyConfig(in.Config)
	clone.MCPTarget = &target
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
// install: a stable per-instance id (re-tagged from the install id), a label
// suffixed with the install's distinguishing config, and that config as a
// request-scoped overlay the dial-time resolver reads. It copies the registry
// and its target so the shared shelf entry is never mutated.
func instanceRegistry(
	shelf *registrydomain.Registry,
	in *installationdomain.Installation,
) *registrydomain.Registry {
	clone := *shelf
	target := *shelf.MCPTarget
	clone.MCPTarget = &target
	clone.ID = ids.From[ids.RegistryKind](in.ID.UUID())
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
