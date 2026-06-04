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
	ID              ids.ConsumerID
	GatewayID       ids.GatewayID
	Name            string
	Type            domain.Type
	Path            string
	Algorithm       string
	EmbeddingConfig *registrydomain.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	Fallback        *domain.Fallback
	ModelPolicies   domain.ModelPolicies
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
	existing.Name = in.Name
	if in.Type != "" {
		existing.Type = in.Type
	}
	existing.Path = in.Path
	existing.Algorithm = in.Algorithm
	existing.EmbeddingConfig = in.EmbeddingConfig
	existing.Headers = in.Headers
	if in.Active != nil {
		existing.Active = *in.Active
	}
	existing.Fallback = in.Fallback
	existing.ModelPolicies = in.ModelPolicies
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
	return nil
}
