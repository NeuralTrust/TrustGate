package registry

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=registry_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*domain.Registry, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Registry, int, error)
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
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*domain.Registry, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if b, ok := cached.(*domain.Registry); ok {
			return scopeToGateway(b, gatewayID)
		}
		f.logger.Warn("backend cache entry failed type assertion; falling back to database",
			slog.String("registry_id", id.String()))
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
func scopeToGateway(b *domain.Registry, gatewayID ids.GatewayID) (*domain.Registry, error) {
	if b.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return b, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Registry, int, error) {
	return f.repo.List(ctx, filter)
}
