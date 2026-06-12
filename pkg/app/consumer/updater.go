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
	Name            *string
	Type            *domain.Type
	Path            *string
	Algorithm       *string
	EmbeddingConfig *registrydomain.EmbeddingConfig
	Headers         *map[string]string
	Active          *bool
	Fallback        *domain.Fallback
	ModelPolicies   *domain.ModelPolicies
	Toolkit         *domain.Toolkit
	FailMode        *domain.FailMode
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
	if in.Type != nil && *in.Type != existing.Type {
		existing.Type = *in.Type
		existing.LLM = nil
		existing.MCP = nil
	}
	if in.Path != nil {
		existing.Path = *in.Path
	}
	if in.Headers != nil {
		existing.Headers = *in.Headers
	}
	if in.Active != nil {
		existing.Active = *in.Active
	}
	applyLLMPolicyUpdate(existing, in)
	applyMCPPolicyUpdate(existing, in)
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

func applyLLMPolicyUpdate(existing *domain.Consumer, in UpdateInput) {
	if in.Algorithm == nil && in.EmbeddingConfig == nil && in.Fallback == nil && in.ModelPolicies == nil {
		return
	}
	if existing.LLM == nil {
		existing.LLM = &domain.LLMPolicy{}
	}
	policy := existing.LLM
	if in.Algorithm != nil {
		policy.Algorithm = *in.Algorithm
	}
	if in.EmbeddingConfig != nil {
		in.EmbeddingConfig.ResolveSecretsFrom(policy.EmbeddingConfig)
		policy.EmbeddingConfig = in.EmbeddingConfig
	}
	if in.Fallback != nil {
		policy.Fallback = in.Fallback
	}
	if in.ModelPolicies != nil {
		policy.ModelPolicies = *in.ModelPolicies
	}
}

func applyMCPPolicyUpdate(existing *domain.Consumer, in UpdateInput) {
	if in.Toolkit == nil && in.FailMode == nil {
		return
	}
	if existing.MCP == nil {
		existing.MCP = &domain.MCPPolicy{}
	}
	policy := existing.MCP
	if in.Toolkit != nil {
		policy.Toolkit = *in.Toolkit
	}
	if in.FailMode != nil {
		policy.FailMode = *in.FailMode
	}
}

func validateRegistryRefsAssociated(c *domain.Consumer) error {
	associated := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		associated[id] = struct{}{}
	}
	if fb := c.Fallback(); fb != nil {
		for _, id := range fb.Chain {
			if _, ok := associated[id]; !ok {
				return fmt.Errorf("%w: fallback chain registry %s is not associated with the consumer",
					registrydomain.ErrInvalidRegistryID, id)
			}
		}
	}
	for id := range c.ModelPolicies() {
		if _, ok := associated[id]; !ok {
			return fmt.Errorf("%w: model_policies registry %s is not associated with the consumer",
				registrydomain.ErrInvalidRegistryID, id)
		}
	}
	for _, e := range c.Toolkit() {
		if _, ok := associated[e.RegistryID]; !ok {
			return fmt.Errorf("%w: toolkit registry %s is not associated with the consumer",
				registrydomain.ErrInvalidRegistryID, e.RegistryID)
		}
	}
	return nil
}
