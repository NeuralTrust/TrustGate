package backend

import (
	"context"
	"log/slog"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type UpdateInput struct {
	ID              uuid.UUID
	GatewayID       uuid.UUID
	Name            string
	Algorithm       string
	Targets         domain.Targets
	EmbeddingConfig *domain.EmbeddingConfig
	HealthChecks    *domain.HealthChecks
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=backend_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Backend, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.BackendTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Backend, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if in.GatewayID != uuid.Nil && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	existing.Name = in.Name
	existing.Algorithm = in.Algorithm
	existing.Targets = in.Targets
	existing.EmbeddingConfig = in.EmbeddingConfig
	existing.HealthChecks = in.HealthChecks
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishBackendCacheInvalidation(ctx, u.publisher, u.logger, existing.GatewayID, existing.ID)
	return existing, nil
}
