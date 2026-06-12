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
	Name            *string
	Provider        *string
	ProviderOptions *map[string]any
	Description     *string
	Weight          *int
	Auth            *domain.TargetAuth
	HealthChecks    *domain.HealthChecks
	MCPTarget       *domain.MCPTarget
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
	if in.Name != nil {
		existing.Name = *in.Name
	}
	if in.Description != nil {
		existing.Description = *in.Description
	}
	if in.Weight != nil {
		existing.Weight = *in.Weight
	}
	applyLLMTargetUpdate(existing, in)
	if in.MCPTarget != nil {
		in.MCPTarget.Normalize()
		in.MCPTarget.ResolveSecretsFrom(existing.MCPTarget)
		existing.MCPTarget = in.MCPTarget
	}
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

func applyLLMTargetUpdate(existing *domain.Registry, in UpdateInput) {
	if in.Provider == nil && in.ProviderOptions == nil && in.Auth == nil && in.HealthChecks == nil {
		return
	}
	if existing.LLMTarget == nil {
		existing.LLMTarget = &domain.LLMTarget{}
	}
	target := existing.LLMTarget
	if in.Provider != nil {
		target.Provider = *in.Provider
	}
	if in.ProviderOptions != nil {
		target.ProviderOptions = *in.ProviderOptions
	}
	if in.Auth != nil {
		in.Auth.ResolveSecretsFrom(target.Auth)
		target.Auth = in.Auth
	}
	if in.HealthChecks != nil {
		target.HealthChecks = in.HealthChecks
	}
}
