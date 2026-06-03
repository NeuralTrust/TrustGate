package registry

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.RegistryID
	GatewayID       ids.GatewayID
	Name            string
	Provider        string
	ProviderOptions map[string]any
	Description     string
	Weight          int
	Auth            *domain.TargetAuth
	HealthChecks    *domain.HealthChecks
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=registry_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Registry, error)
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
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Registry, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	existing.Name = in.Name
	existing.Provider = in.Provider
	existing.ProviderOptions = in.ProviderOptions
	existing.Description = in.Description
	existing.Weight = in.Weight
	existing.Auth = in.Auth
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
