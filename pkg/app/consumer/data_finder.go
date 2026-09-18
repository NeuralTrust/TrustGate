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

package consumer

import (
	"context"
	"log/slog"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"golang.org/x/sync/singleflight"
)

//go:generate mockery --name=DataFinder --dir=. --output=./mocks --filename=data_finder_mock.go --case=underscore --with-expecter
type DataFinder interface {
	FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*Data, error)
}

var _ DataFinder = (*dataFinder)(nil)

type dataFinder struct {
	repo           domain.Reader
	registryRepo   registrydomain.Repository
	policyRepo     policydomain.Repository
	authRepo       authdomain.Repository
	pluginRegistry appplugins.Registry
	memoryCache    *cache.TTLMap
	logger         *slog.Logger
	sf             singleflight.Group
}

func NewDataFinder(
	repo domain.Reader,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	pluginRegistry appplugins.Registry,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) DataFinder {
	return &dataFinder{
		repo:           repo,
		registryRepo:   registryRepo,
		policyRepo:     policyRepo,
		authRepo:       authRepo,
		pluginRegistry: pluginRegistry,
		memoryCache:    manager.GetTTLMap(cache.ConsumerDataTTLName),
		logger:         logger,
	}
}

func (f *dataFinder) FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*Data, error) {
	key := gatewayID.String()
	if data, ok := f.cached(key); ok {
		return data, nil
	}
	v, err, _ := f.sf.Do(key, func() (interface{}, error) {
		if data, ok := f.cached(key); ok {
			return data, nil
		}
		return f.load(ctx, gatewayID, key)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Data), nil
}

func (f *dataFinder) cached(key string) (*Data, bool) {
	cached, ok := f.memoryCache.Get(key)
	if !ok {
		return nil, false
	}
	data, ok := cached.(*Data)
	if !ok {
		f.logger.Warn("consumer-data cache entry failed type assertion; falling back to database",
			slog.String("gateway_id", key))
		f.memoryCache.Delete(key)
		return nil, false
	}
	return data, true
}

func (f *dataFinder) load(ctx context.Context, gatewayID ids.GatewayID, key string) (*Data, error) {
	consumers, err := f.repo.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}

	backendByID, err := f.loadBackends(ctx, gatewayID, consumers)
	if err != nil {
		return nil, err
	}
	globalPolicies, policiesByConsumer, err := f.loadPolicies(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	authByID, err := f.loadAuths(ctx, gatewayID, consumers)
	if err != nil {
		return nil, err
	}

	globals := partitionScoped(globalPolicies)
	routable := make([]RoutableConsumer, 0, len(consumers))
	for _, c := range consumers {
		chain := fallbackChainOf(c)
		fallbackBackends := collectBackends(chain, backendByID)
		f.warnUnresolvedFallbackChain(c, fallbackBackends)
		attached := partitionScoped(policiesByConsumer[c.ID])
		unscoped := composePolicies(globals.unscoped, attached.unscoped)
		scoped := mergeScoped(attached.scoped, globals.scoped)
		policies, plan, mcpPlans := f.plansFor(c, unscoped, scoped, mergeScoped(attached.crossing, globals.crossing))
		routable = append(routable, RoutableConsumer{
			Consumer:         c,
			Registries:       collectBackends(poolRegistryIDs(c.RegistryIDs, chain), backendByID),
			FallbackBackends: fallbackBackends,
			Policies:         policies,
			PolicyPlan:       plan,
			ScopedPolicies:   scoped,
			MCPPlans:         mcpPlans,
			Auths:            collectAuths(c.AuthIDs, authByID),
		})
	}

	data := NewData(gatewayID, routable)
	data.StoreConsumer = &RoutableConsumer{
		Consumer:       domain.BuildStoreConsumer(gatewayID),
		Policies:       globals.unscoped,
		PolicyPlan:     f.buildPolicyPlan(globals.unscoped),
		ScopedPolicies: globals.scoped,
		MCPPlans:       BuildPolicyPlans(f.pluginRegistry, globals.unscoped, globals.scoped, f.logger),
	}
	data.SetRegistryIndex(backendByID)
	f.memoryCache.Set(key, data)
	return data, nil
}

func (f *dataFinder) buildPolicyPlan(policies []*policydomain.Policy) *appplugins.StagePlan {
	if f.pluginRegistry == nil {
		return nil
	}
	return appplugins.NewStagePlan(f.pluginRegistry, policies, f.logger)
}

func (f *dataFinder) buildMCPPlans(c *domain.Consumer, unscoped, scoped []*policydomain.Policy) *PolicyPlans {
	if c == nil || c.Type != domain.TypeMCP {
		return nil
	}
	return BuildPolicyPlans(f.pluginRegistry, unscoped, scoped, f.logger)
}

// plansFor resolves what a consumer runs. An MCP consumer keeps the split it
// has always had: the unscoped policies are its chain and the scoped ones are
// selected per destination on tools/call. Any other consumer folds the crossing
// policies into a single set that is both its Policies and its PolicyPlan
// (RUN-1621, §2.1).
func (f *dataFinder) plansFor(
	c *domain.Consumer,
	unscoped, scoped, crossing []*policydomain.Policy,
) ([]*policydomain.Policy, *appplugins.StagePlan, *PolicyPlans) {
	if c == nil || c.Type == domain.TypeMCP {
		return unscoped, f.buildPolicyPlan(unscoped), f.buildMCPPlans(c, unscoped, scoped)
	}
	policies := f.inertPolicies(c, unscoped, crossing)
	return policies, appplugins.NewInertStagePlan(f.pluginRegistry, policies, f.logger), nil
}

// inertPolicies is the set a non-MCP consumer runs: its unscoped policies plus
// the crossing ones that survive the plugin opt-in and the coalescence. A
// destination scope never reaches here, whether it arrived by attach or by
// global (RUN-1621, rule 7), and neither does a tombstone (rule 1):
// partitionScoped keeps both out of the crossing bucket.
func (f *dataFinder) inertPolicies(c *domain.Consumer, unscoped, crossing []*policydomain.Policy) []*policydomain.Policy {
	inert := f.coalesceInert(c, unscoped, f.inertSafeOnly(crossing))
	if len(inert) == 0 {
		return unscoped
	}
	out := make([]*policydomain.Policy, 0, len(unscoped)+len(inert))
	out = append(out, unscoped...)
	return append(out, inert...)
}

// inertSafeOnly drops the policies whose plugin gates by tool or registry name
// (RUN-1621, rule 2). The opt-in is a default deny, so an unknown plugin and an
// absent registry both drop everything.
func (f *dataFinder) inertSafeOnly(crossing []*policydomain.Policy) []*policydomain.Policy {
	out := make([]*policydomain.Policy, 0, len(crossing))
	for _, p := range crossing {
		if appplugins.IsInertSafe(f.pluginRegistry, p.Slug) {
			out = append(out, p)
		}
	}
	return out
}

// coalesceInert resolves the collisions inertness creates. A crossing policy
// loses its group outside MCP, so policies the level guard accepted as distinct
// land on the same one. Three cases, in this order (RUN-1621, rule 3.6): an
// unscoped policy of the same slug was written for exactly that traffic and
// wins; a single collapsed policy runs, which is the requirement; two or more
// contradict each other and none runs, because executing an arbitrary one is
// worse than executing neither. A disabled policy occupies no level, the same
// exemption the write-side guard makes, so it neither wins a collision nor
// causes one.
func (f *dataFinder) coalesceInert(c *domain.Consumer, unscoped, crossing []*policydomain.Policy) []*policydomain.Policy {
	if len(crossing) == 0 {
		return nil
	}
	unscopedSlugs := make(map[string]struct{}, len(unscoped))
	for _, p := range unscoped {
		if p.Enabled {
			unscopedSlugs[p.Slug] = struct{}{}
		}
	}
	order := make([]string, 0, len(crossing))
	bySlug := make(map[string][]*policydomain.Policy, len(crossing))
	for _, p := range crossing {
		if !p.Enabled {
			continue
		}
		if _, seen := bySlug[p.Slug]; !seen {
			order = append(order, p.Slug)
		}
		bySlug[p.Slug] = append(bySlug[p.Slug], p)
	}
	out := make([]*policydomain.Policy, 0, len(order))
	for _, slug := range order {
		group := bySlug[slug]
		if _, overridden := unscopedSlugs[slug]; overridden {
			f.warnCoalesced(c, slug, group,
				"scope-bound policies collapse onto an unscoped policy of the same slug outside MCP; only the unscoped one runs")
			continue
		}
		if len(group) > 1 {
			f.warnCoalesced(c, slug, group,
				"scope-bound policies collapse onto the same level outside MCP and none of them runs; give them distinct consumers or merge them")
			continue
		}
		out = append(out, group[0])
	}
	return out
}

func (f *dataFinder) warnCoalesced(c *domain.Consumer, slug string, group []*policydomain.Policy, msg string) {
	names := make([]string, 0, len(group))
	policyIDs := make([]string, 0, len(group))
	for _, p := range group {
		names = append(names, p.Name)
		policyIDs = append(policyIDs, p.ID.String())
	}
	attrs := []any{
		slog.String("slug", slug),
		slog.Any("policy_names", names),
		slog.Any("policy_ids", policyIDs),
	}
	if c != nil {
		attrs = append(attrs, slog.String("consumer_id", c.ID.String()))
	}
	f.logger.Warn(msg, attrs...)
}

func (f *dataFinder) loadBackends(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumers []*domain.Consumer,
) (map[ids.RegistryID]*registrydomain.Registry, error) {
	idList := uniqueIDs(consumers, func(c *domain.Consumer) []ids.RegistryID {
		return append(append([]ids.RegistryID{}, c.RegistryIDs...), fallbackChainOf(c)...)
	})
	if len(idList) == 0 {
		return map[ids.RegistryID]*registrydomain.Registry{}, nil
	}
	found, err := f.registryRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return nil, err
	}
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(found))
	for _, b := range found {
		if !b.Enabled {
			continue
		}
		byID[b.ID] = b
	}
	return byID, nil
}

func (f *dataFinder) loadPolicies(
	ctx context.Context,
	gatewayID ids.GatewayID,
) ([]*policydomain.Policy, map[ids.ConsumerID][]*policydomain.Policy, error) {
	all, err := f.policyRepo.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, nil, err
	}
	globals := make([]*policydomain.Policy, 0)
	byConsumer := make(map[ids.ConsumerID][]*policydomain.Policy)
	for _, p := range all {
		if p == nil {
			continue
		}
		if p.IsGlobal() {
			globals = append(globals, p)
			continue
		}
		for _, cid := range p.ConsumerIDs {
			byConsumer[cid] = append(byConsumer[cid], p)
		}
	}
	return globals, byConsumer, nil
}

func (f *dataFinder) loadAuths(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumers []*domain.Consumer,
) (map[ids.AuthID]*authdomain.Auth, error) {
	idList := uniqueIDs(consumers, func(c *domain.Consumer) []ids.AuthID { return c.AuthIDs })
	if len(idList) == 0 {
		return map[ids.AuthID]*authdomain.Auth{}, nil
	}
	found, err := f.authRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return nil, err
	}
	byID := make(map[ids.AuthID]*authdomain.Auth, len(found))
	for _, a := range found {
		byID[a.ID] = a
	}
	return byID, nil
}

func uniqueIDs[T comparable](consumers []*domain.Consumer, pick func(*domain.Consumer) []T) []T {
	seen := make(map[T]struct{})
	out := make([]T, 0)
	for _, c := range consumers {
		for _, id := range pick(c) {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func (f *dataFinder) warnUnresolvedFallbackChain(c *domain.Consumer, resolved []*registrydomain.Registry) {
	chain := fallbackChainOf(c)
	if len(chain) == len(resolved) {
		return
	}
	f.logger.Warn("consumer fallback chain has unresolved or disabled backend(s); skipping them",
		slog.String("consumer_id", c.ID.String()),
		slog.Int("chain_size", len(chain)),
		slog.Int("resolved", len(resolved)),
	)
}

func fallbackChainOf(c *domain.Consumer) []ids.RegistryID {
	if c == nil {
		return nil
	}
	fb := c.Fallback
	if fb == nil || !fb.Enabled {
		return nil
	}
	return []ids.RegistryID(fb.Chain)
}

func poolRegistryIDs(all []ids.RegistryID, chain []ids.RegistryID) []ids.RegistryID {
	if len(chain) == 0 {
		return all
	}
	excluded := make(map[ids.RegistryID]struct{}, len(chain))
	for _, id := range chain {
		excluded[id] = struct{}{}
	}
	out := make([]ids.RegistryID, 0, len(all))
	for _, id := range all {
		if _, skip := excluded[id]; skip {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return all
	}
	return out
}

func collectBackends(idList []ids.RegistryID, byID map[ids.RegistryID]*registrydomain.Registry) []*registrydomain.Registry {
	out := make([]*registrydomain.Registry, 0, len(idList))
	for _, id := range idList {
		if b, ok := byID[id]; ok {
			out = append(out, b)
		}
	}
	return out
}

// scopeBuckets splits a policy list by how far its mcp_scope reaches: unscoped
// policies run on every plane, crossing ones narrow by group alone and so also
// reach a non-MCP plane, mcpOnly ones name a registry or a tool and cannot
// leave MCP, and dormant ones are tombstones that run nowhere. scoped is the
// three scoped buckets in load order, which is what the MCP plane selects
// among; tombstones stay in it so a policy pruned to {} is reported as skipped
// instead of vanishing.
type scopeBuckets struct {
	unscoped []*policydomain.Policy
	crossing []*policydomain.Policy
	mcpOnly  []*policydomain.Policy
	dormant  []*policydomain.Policy
	scoped   []*policydomain.Policy
}

func partitionScoped(policies []*policydomain.Policy) scopeBuckets {
	buckets := scopeBuckets{unscoped: make([]*policydomain.Policy, 0, len(policies))}
	for _, p := range policies {
		if p == nil {
			continue
		}
		switch {
		case p.MCPScope == nil:
			buckets.unscoped = append(buckets.unscoped, p)
			continue
		case p.Dormant():
			buckets.dormant = append(buckets.dormant, p)
		case p.MCPScope.CrossesPlanes():
			buckets.crossing = append(buckets.crossing, p)
		default:
			buckets.mcpOnly = append(buckets.mcpOnly, p)
		}
		buckets.scoped = append(buckets.scoped, p)
	}
	return buckets
}

func mergeScoped(consumerScoped, globalsScoped []*policydomain.Policy) []*policydomain.Policy {
	if len(consumerScoped)+len(globalsScoped) == 0 {
		return nil
	}
	out := make([]*policydomain.Policy, 0, len(consumerScoped)+len(globalsScoped))
	seenIDs := make(map[ids.PolicyID]struct{}, len(consumerScoped)+len(globalsScoped))
	for _, list := range [][]*policydomain.Policy{consumerScoped, globalsScoped} {
		for _, p := range list {
			if _, dup := seenIDs[p.ID]; dup {
				continue
			}
			seenIDs[p.ID] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func composePolicies(globals, consumerScoped []*policydomain.Policy) []*policydomain.Policy {
	out := make([]*policydomain.Policy, 0, len(globals)+len(consumerScoped))
	overriddenSlugs := make(map[string]struct{}, len(consumerScoped))
	seenIDs := make(map[ids.PolicyID]struct{}, len(globals)+len(consumerScoped))
	for _, p := range consumerScoped {
		if _, dup := seenIDs[p.ID]; dup {
			continue
		}
		seenIDs[p.ID] = struct{}{}
		overriddenSlugs[p.Slug] = struct{}{}
		out = append(out, p)
	}
	for _, p := range globals {
		if _, dup := seenIDs[p.ID]; dup {
			continue
		}
		if _, ok := overriddenSlugs[p.Slug]; ok {
			continue
		}
		seenIDs[p.ID] = struct{}{}
		out = append(out, p)
	}
	return out
}

func collectAuths(idList []ids.AuthID, byID map[ids.AuthID]*authdomain.Auth) []*authdomain.Auth {
	out := make([]*authdomain.Auth, 0, len(idList))
	for _, id := range idList {
		if a, ok := byID[id]; ok {
			out = append(out, a)
		}
	}
	return out
}
