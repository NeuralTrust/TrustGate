package consumer

import (
	"context"
	"log/slog"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=DataFinder --dir=. --output=./mocks --filename=data_finder_mock.go --case=underscore --with-expecter
type DataFinder interface {
	FindByGateway(ctx context.Context, gatewayID uuid.UUID) (*Data, error)
}

var _ DataFinder = (*dataFinder)(nil)

type dataFinder struct {
	repo        domain.Repository
	policyRepo  policydomain.Repository
	authRepo    authdomain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewDataFinder(
	repo domain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) DataFinder {
	return &dataFinder{
		repo:        repo,
		policyRepo:  policyRepo,
		authRepo:    authRepo,
		memoryCache: manager.GetTTLMap(cache.ConsumerDataTTLName),
		logger:      logger,
	}
}

func (f *dataFinder) FindByGateway(ctx context.Context, gatewayID uuid.UUID) (*Data, error) {
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
		routable = append(routable, RoutableConsumer{
			Consumer: c,
			Policies: collectPolicies(c.PolicyIDs, policyByID),
			Auths:    collectAuths(c.AuthIDs, authByID),
		})
	}

	data := &Data{GatewayID: gatewayID, Consumers: routable}
	f.memoryCache.Set(key, data)
	return data, nil
}

// loadPolicies batch-resolves the gateway's policies in one query (no N+1), or
// none when no consumer references a policy.
func (f *dataFinder) loadPolicies(
	ctx context.Context,
	gatewayID uuid.UUID,
	consumers []*domain.Consumer,
) (map[uuid.UUID]*policydomain.Policy, error) {
	ids := uniqueIDs(consumers, func(c *domain.Consumer) []uuid.UUID { return c.PolicyIDs })
	if len(ids) == 0 {
		return map[uuid.UUID]*policydomain.Policy{}, nil
	}
	found, err := f.policyRepo.FindByIDs(ctx, gatewayID, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]*policydomain.Policy, len(found))
	for _, p := range found {
		byID[p.ID] = p
	}
	return byID, nil
}

func (f *dataFinder) loadAuths(
	ctx context.Context,
	gatewayID uuid.UUID,
	consumers []*domain.Consumer,
) (map[uuid.UUID]*authdomain.Auth, error) {
	ids := uniqueIDs(consumers, func(c *domain.Consumer) []uuid.UUID { return c.AuthIDs })
	if len(ids) == 0 {
		return map[uuid.UUID]*authdomain.Auth{}, nil
	}
	found, err := f.authRepo.FindByIDs(ctx, gatewayID, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]*authdomain.Auth, len(found))
	for _, a := range found {
		byID[a.ID] = a
	}
	return byID, nil
}

func uniqueIDs(consumers []*domain.Consumer, pick func(*domain.Consumer) []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{})
	out := make([]uuid.UUID, 0)
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

func collectPolicies(ids []uuid.UUID, byID map[uuid.UUID]*policydomain.Policy) []*policydomain.Policy {
	out := make([]*policydomain.Policy, 0, len(ids))
	for _, id := range ids {
		if p, ok := byID[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func collectAuths(ids []uuid.UUID, byID map[uuid.UUID]*authdomain.Auth) []*authdomain.Auth {
	out := make([]*authdomain.Auth, 0, len(ids))
	for _, id := range ids {
		if a, ok := byID[id]; ok {
			out = append(out, a)
		}
	}
	return out
}
