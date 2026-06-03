package consumer

import (
	"context"
	"log/slog"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=DataFinder --dir=. --output=./mocks --filename=data_finder_mock.go --case=underscore --with-expecter
type DataFinder interface {
	FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*Data, error)
}

var _ DataFinder = (*dataFinder)(nil)

type dataFinder struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	policyRepo   policydomain.Repository
	authRepo     authdomain.Repository
	memoryCache  *cache.TTLMap
	logger       *slog.Logger
}

func NewDataFinder(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) DataFinder {
	return &dataFinder{
		repo:         repo,
		registryRepo: registryRepo,
		policyRepo:   policyRepo,
		authRepo:     authRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerDataTTLName),
		logger:       logger,
	}
}

func (f *dataFinder) FindByGateway(ctx context.Context, gatewayID ids.GatewayID) (*Data, error) {
	key := gatewayID.String()
	if cached, ok := f.memoryCache.Get(key); ok {
		if data, ok := cached.(*Data); ok {
			return data, nil
		}
		f.logger.Warn("consumer-data cache entry failed type assertion; falling back to database",
			slog.String("gateway_id", key))
		f.memoryCache.Delete(key)
	}

	consumers, err := f.repo.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}

	backendByID, err := f.loadBackends(ctx, gatewayID, consumers)
	if err != nil {
		return nil, err
	}
	policyByID, err := f.loadPolicies(ctx, gatewayID, consumers)
	if err != nil {
		return nil, err
	}
	authByID, err := f.loadAuths(ctx, gatewayID, consumers)
	if err != nil {
		return nil, err
	}

	routable := make([]RoutableConsumer, 0, len(consumers))
	for _, c := range consumers {
		fallbackBackends := collectBackends(fallbackChainOf(c), backendByID)
		f.warnUnresolvedFallbackChain(c, fallbackBackends)
		routable = append(routable, RoutableConsumer{
			Consumer:         c,
			Registries:       collectBackends(c.RegistryIDs, backendByID),
			FallbackBackends: fallbackBackends,
			Policies:         collectPolicies(c.PolicyIDs, policyByID),
			Auths:            collectAuths(c.AuthIDs, authByID),
		})
	}

	data := NewData(gatewayID, routable)
	f.memoryCache.Set(key, data)
	return data, nil
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
		byID[b.ID] = b
	}
	return byID, nil
}

func (f *dataFinder) loadPolicies(
	ctx context.Context,
	gatewayID ids.GatewayID,
	consumers []*domain.Consumer,
) (map[ids.PolicyID]*policydomain.Policy, error) {
	idList := uniqueIDs(consumers, func(c *domain.Consumer) []ids.PolicyID { return c.PolicyIDs })
	if len(idList) == 0 {
		return map[ids.PolicyID]*policydomain.Policy{}, nil
	}
	found, err := f.policyRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return nil, err
	}
	byID := make(map[ids.PolicyID]*policydomain.Policy, len(found))
	for _, p := range found {
		byID[p.ID] = p
	}
	return byID, nil
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
	f.logger.Warn("consumer fallback chain references unknown backend(s); skipping them",
		slog.String("consumer_id", c.ID.String()),
		slog.Int("chain_size", len(chain)),
		slog.Int("resolved", len(resolved)),
	)
}

func fallbackChainOf(c *domain.Consumer) []ids.RegistryID {
	if c == nil || c.Fallback == nil || !c.Fallback.Enabled {
		return nil
	}
	return []ids.RegistryID(c.Fallback.Chain)
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

func collectPolicies(idList []ids.PolicyID, byID map[ids.PolicyID]*policydomain.Policy) []*policydomain.Policy {
	out := make([]*policydomain.Policy, 0, len(idList))
	for _, id := range idList {
		if p, ok := byID[id]; ok {
			out = append(out, p)
		}
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
