package consumer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID            ids.ConsumerID
	GatewayID     ids.GatewayID
	Name          *string
	Type          *domain.Type
	Path          *string
	RoutingMode   *domain.RoutingMode
	LBConfig      *domain.LBConfig
	Headers       *map[string]string
	Active        *bool
	Fallback      *domain.Fallback
	ModelPolicies *domain.ModelPolicies
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
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
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error) {
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
	if in.Type != nil {
		existing.Type = *in.Type
	}
	if in.Path != nil {
		existing.Path = *in.Path
	}
	previousMode := existing.RoutingMode
	if in.RoutingMode != nil {
		existing.RoutingMode = *in.RoutingMode
	}
	if in.LBConfig != nil {
		resolveLBConfigSecrets(in.LBConfig, existing.LBConfig)
		existing.LBConfig = in.LBConfig
	}
	if in.Headers != nil {
		existing.Headers = *in.Headers
	}
	if in.Active != nil {
		existing.Active = *in.Active
	}
	if in.Fallback != nil {
		existing.Fallback = in.Fallback
	}
	if in.ModelPolicies != nil {
		existing.ModelPolicies = *in.ModelPolicies
	}
	if previousMode != existing.RoutingMode {
		cleanIncompatibleModeConfig(existing)
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := validateRegistryRefsAssociated(existing); err != nil {
		return nil, err
	}
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, existing.GatewayID)
	return existing, nil
}

func validateRegistryRefsAssociated(c *domain.Consumer) error {
	if c.RoutingMode == domain.RoutingModeRoleBased {
		return nil
	}
	associated := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		associated[id] = struct{}{}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			if _, ok := associated[id]; !ok {
				return fmt.Errorf("%w: fallback chain registry %s is not associated with the consumer",
					registrydomain.ErrInvalidRegistryID, id)
			}
		}
	}
	for id := range c.ModelPolicies {
		if _, ok := associated[id]; !ok {
			return fmt.Errorf("%w: model_policies registry %s is not associated with the consumer",
				registrydomain.ErrInvalidRegistryID, id)
		}
	}
	if c.LBConfig != nil {
		for _, member := range c.LBConfig.Members {
			if _, ok := associated[member.RegistryID]; !ok {
				return fmt.Errorf("%w: lb_config member registry %s is not associated with the consumer",
					registrydomain.ErrInvalidRegistryID, member.RegistryID)
			}
		}
	}
	return nil
}

func cleanIncompatibleModeConfig(c *domain.Consumer) {
	switch c.RoutingMode {
	case domain.RoutingModeRoleBased:
		c.RegistryIDs = nil
		c.Fallback = nil
		c.LBConfig = nil
		c.ModelPolicies = nil
	case domain.RoutingModeInline:
		c.RoleIDs = nil
	}
}

func resolveLBConfigSecrets(next, prev *domain.LBConfig) {
	if next == nil || next.EmbeddingConfig == nil {
		return
	}
	if prev == nil {
		next.EmbeddingConfig.ResolveSecretsFrom(nil)
		return
	}
	next.EmbeddingConfig.ResolveSecretsFrom(prev.EmbeddingConfig)
}
