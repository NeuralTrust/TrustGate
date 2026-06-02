package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error)
}

var _ Finder = (*finder)(nil)

type finder struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Finder {
	return &finder{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if g, ok := cached.(*domain.Gateway); ok {
			return g, nil
		}
		f.logger.Warn("gateway cache entry failed type assertion; falling back to database",
			slog.String("gateway_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	g, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), g)
	return g, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error) {
	return f.repo.List(ctx, filter)
}
