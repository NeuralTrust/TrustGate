package backend

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=backend_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, gatewayID, id uuid.UUID) (*domain.Backend, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Backend, int, error)
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
		memoryCache: manager.GetTTLMap(cache.BackendTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, gatewayID, id uuid.UUID) (*domain.Backend, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if b, ok := cached.(*domain.Backend); ok {
			return scopeToGateway(b, gatewayID)
		}
		f.logger.Warn("backend cache entry failed type assertion; falling back to database",
			slog.String("backend_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	b, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), b)
	return scopeToGateway(b, gatewayID)
}

// scopeToGateway enforces that a backend belongs to the requesting gateway,
// returning ErrNotFound (not a distinct error) for cross-gateway ids so the API
// never confirms the existence of another gateway's resource.
func scopeToGateway(b *domain.Backend, gatewayID uuid.UUID) (*domain.Backend, error) {
	if b.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return b, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Backend, int, error) {
	return f.repo.List(ctx, filter)
}
