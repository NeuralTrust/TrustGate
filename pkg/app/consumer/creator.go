package consumer

import (
	"context"
	"fmt"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID     ids.GatewayID
	Name          string
	Type          domain.Type
	Path          string
	RoutingMode   domain.RoutingMode
	LBConfig      *domain.LBConfig
	Headers       map[string]string
	Active        *bool
	Fallback      *domain.Fallback
	RegistryIDs   []ids.RegistryID
	ModelPolicies domain.ModelPolicies
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=consumer_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Consumer, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:         repo,
		registryRepo: registryRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:    publisher,
		logger:       logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	cons, err := domain.New(domain.CreateParams{
		GatewayID:     in.GatewayID,
		Name:          in.Name,
		Type:          in.Type,
		Path:          in.Path,
		RoutingMode:   in.RoutingMode,
		LBConfig:      in.LBConfig,
		Headers:       in.Headers,
		Active:        in.Active,
		Fallback:      in.Fallback,
		RegistryIDs:   in.RegistryIDs,
		ModelPolicies: in.ModelPolicies,
	})
	if err != nil {
		return nil, err
	}
	if err := validateRegistryRefsAssociated(cons); err != nil {
		return nil, err
	}
	if err := c.ensureRegistriesInGateway(ctx, in.GatewayID, in.RegistryIDs); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, cons); err != nil {
		return nil, err
	}
	c.memoryCache.Set(cons.ID.String(), cons)
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, cons.GatewayID)
	return cons, nil
}

func (c *creator) ensureRegistriesInGateway(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) error {
	if len(registryIDs) == 0 {
		return nil
	}
	found, err := c.registryRepo.FindByIDs(ctx, gatewayID, registryIDs)
	if err != nil {
		return err
	}
	if len(found) != len(registryIDs) {
		return fmt.Errorf("%w: one or more registries do not belong to the gateway", registrydomain.ErrInvalidRegistryID)
	}
	return nil
}
