package registry

import (
	"context"
	"log/slog"
	"strings"
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
	applyMCPTargetUpdate(existing, in)
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

// applyMCPTargetUpdate merges the incoming mcp_target over the stored one so
// a partial payload (e.g. only url) does not silently wipe transport, headers
// or the auth block with its credentials. Auth is cleared explicitly with
// {"mode": "none"}; headers with an empty object.
func applyMCPTargetUpdate(existing *domain.Registry, in UpdateInput) {
	if in.MCPTarget == nil {
		return
	}
	incoming := in.MCPTarget
	if prev := existing.MCPTarget; prev != nil {
		if strings.TrimSpace(incoming.URL) == "" {
			incoming.URL = prev.URL
		}
		if incoming.Transport == "" {
			incoming.Transport = prev.Transport
		}
		if incoming.Headers == nil {
			incoming.Headers = prev.Headers
		}
		if incoming.Auth == nil {
			incoming.Auth = prev.Auth
		}
	}
	incoming.Normalize()
	incoming.ResolveSecretsFrom(existing.MCPTarget)
	existing.MCPTarget = incoming
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
