package consumer

import (
	"context"
	"log/slog"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"golang.org/x/sync/singleflight"
)

//go:generate mockery --name=DataFinder --dir=. --output=./mocks --filename=data_finder_mock.go --case=underscore --with-expecter
type DataFinder interface {
	FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*Data, error)
}

var _ DataFinder = (*dataFinder)(nil)

type dataFinder struct {
	repo           domain.Repository
	registryRepo   registrydomain.Repository
	policyRepo     policydomain.Repository
	authRepo       authdomain.Repository
	roleRepo       roledomain.Repository
	pluginRegistry appplugins.Registry
	memoryCache    *cache.TTLMap
	logger         *slog.Logger
	sf             singleflight.Group
}

func NewDataFinder(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	roleRepo roledomain.Repository,
	pluginRegistry appplugins.Registry,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) DataFinder {
	return &dataFinder{
		repo:           repo,
		registryRepo:   registryRepo,
		policyRepo:     policyRepo,
		authRepo:       authRepo,
		roleRepo:       roleRepo,
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

	roles, err := f.loadRoles(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	backendByID, err := f.loadBackends(ctx, gatewayID, consumers, roles)
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

	routable := make([]RoutableConsumer, 0, len(consumers))
	for _, c := range consumers {
		chain := fallbackChainOf(c)
		fallbackBackends := collectBackends(chain, backendByID)
		f.warnUnresolvedFallbackChain(c, fallbackBackends)
		policies := composePolicies(globalPolicies, policiesByConsumer[c.ID])
		routable = append(routable, RoutableConsumer{
			Consumer:         c,
			Registries:       collectBackends(poolRegistryIDs(c.RegistryIDs, chain), backendByID),
			FallbackBackends: fallbackBackends,
			Policies:         policies,
			PolicyPlan:       f.buildPolicyPlan(policies),
			Auths:            collectAuths(c.AuthIDs, authByID),
		})
	}

	data := NewData(gatewayID, routable, roles)
	data.SetRegistryIndex(backendByID)
	f.memoryCache.Set(key, data)
	return data, nil
}

func (f *dataFinder) buildPolicyPlan(policies []*policydomain.Policy) *appplugins.StagePlan {
	if f.pluginRegistry == nil {
		return nil
	}
	return appplugins.NewStagePlan(f.pluginRegistry, policies)
}

func (f *dataFinder) loadBackends(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumers []*domain.Consumer,
	roles []*roledomain.Role,
) (map[ids.RegistryID]*registrydomain.Registry, error) {
	idList := uniqueIDs(consumers, func(c *domain.Consumer) []ids.RegistryID {
		return append(append([]ids.RegistryID{}, c.RegistryIDs...), fallbackChainOf(c)...)
	})
	idList = appendRoleRegistryIDs(idList, roles)
	if len(idList) == 0 {
		return map[ids.RegistryID]*registrydomain.Registry{}, nil
	}
	found, err := f.registryRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return nil, err
	}
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(found))
	for _, b := range found {
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

func (f *dataFinder) loadRoles(ctx context.Context, gatewayID ids.GatewayID) ([]*roledomain.Role, error) {
	if f.roleRepo == nil {
		return nil, nil
	}
	return f.roleRepo.ListByGateway(ctx, gatewayID)
}

func appendRoleRegistryIDs(idList []ids.RegistryID, roles []*roledomain.Role) []ids.RegistryID {
	seen := make(map[ids.RegistryID]struct{}, len(idList))
	for _, id := range idList {
		seen[id] = struct{}{}
	}
	for _, r := range roles {
		if r == nil {
			continue
		}
		for _, id := range r.RegistryIDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			idList = append(idList, id)
		}
	}
	return idList
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
	f.logger.Warn("consumer fallback chain references unknown backend(s); skipping them",
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
