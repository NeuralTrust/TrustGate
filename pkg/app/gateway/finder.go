package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter

// Finder reads gateways. FindByID follows the cache-first pattern:
// look up the in-process TTL map, fall back to the repository on miss
// or type-assertion error, then prime the cache. List is intentionally
// uncached — pages move and substring filters are too varied to make
// per-call caching worthwhile.
//
// RUN-291 will insert a Redis hit between the memory cache and the
// repository. The contract here does not change.
type Finder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Gateway, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error)
}

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

func (f *finder) FindByID(ctx context.Context, id uuid.UUID) (*domain.Gateway, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if g, ok := cached.(*domain.Gateway); ok {
			return g, nil
		}
		// Defensive: if the type assertion fails the slot has been
		// poisoned by a bug elsewhere; drop the entry and fall through
		// to the database rather than serving a stale or wrong type.
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
