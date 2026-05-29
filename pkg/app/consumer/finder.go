package consumer

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=consumer_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Consumer, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Consumer, int, error)
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
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, id uuid.UUID) (*domain.Consumer, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if c, ok := cached.(*domain.Consumer); ok {
			return c, nil
		}
		f.logger.Warn("consumer cache entry failed type assertion; falling back to database",
			slog.String("consumer_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	c, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), c)
	return c, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Consumer, int, error) {
	return f.repo.List(ctx, filter)
}
