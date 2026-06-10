package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=gateway_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, id ids.GatewayID) error
}

var _ Deleter = (*deleter)(nil)

type deleter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewDeleter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Deleter {
	return &deleter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (d *deleter) Delete(ctx context.Context, id ids.GatewayID) error {
	g, _ := cachedGatewayForDelete(d.memoryCache, id)
	if err := d.repo.Delete(ctx, id); err != nil {
		return err
	}
	deleteGatewayCache(d.memoryCache, g)
	d.memoryCache.Delete(gatewayIDCacheKey(id))
	d.memoryCache.Delete(id.String())
	publishGatewayDataInvalidation(ctx, d.publisher, d.logger, id)
	return nil
}

func cachedGatewayForDelete(memoryCache *cache.TTLMap, id ids.GatewayID) (*domain.Gateway, bool) {
	for _, key := range []string{gatewayIDCacheKey(id), id.String()} {
		cached, ok := memoryCache.Get(key)
		if !ok {
			continue
		}
		g, ok := cached.(*domain.Gateway)
		if ok {
			return g, true
		}
	}
	return nil, false
}
