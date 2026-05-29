package policy

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=policy_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Policy, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error)
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
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, id uuid.UUID) (*domain.Policy, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if p, ok := cached.(*domain.Policy); ok {
			return p, nil
		}
		f.logger.Warn("policy cache entry failed type assertion; falling back to database",
			slog.String("policy_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	p, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), p)
	return p, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error) {
	return f.repo.List(ctx, filter)
}
