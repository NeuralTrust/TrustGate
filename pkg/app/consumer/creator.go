package consumer

import (
	"context"
	"fmt"
	"log/slog"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            domain.Type
	Path            string
	Algorithm       string
	EmbeddingConfig *registrydomain.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	RegistryIDs     []ids.RegistryID
	PolicyIDs       []ids.PolicyID
	AuthIDs         []ids.AuthID
	Fallback        *domain.Fallback
	ModelPolicies   domain.ModelPolicies
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=consumer_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Consumer, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	policyRepo   policydomain.Repository
	authRepo     authdomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:         repo,
		registryRepo: registryRepo,
		policyRepo:   policyRepo,
		authRepo:     authRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:    publisher,
		logger:       logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	if err := validateAssociations(ctx, c.registryRepo, c.policyRepo, c.authRepo,
		in.GatewayID, in.RegistryIDs, in.PolicyIDs, in.AuthIDs, fallbackChainIDs(in.Fallback)); err != nil {
		return nil, err
	}
	cons, err := domain.New(domain.CreateParams{
		GatewayID:       in.GatewayID,
		Name:            in.Name,
		Type:            in.Type,
		Path:            in.Path,
		Algorithm:       in.Algorithm,
		EmbeddingConfig: in.EmbeddingConfig,
		Headers:         in.Headers,
		Active:          in.Active,
		RegistryIDs:     in.RegistryIDs,
		PolicyIDs:       in.PolicyIDs,
		AuthIDs:         in.AuthIDs,
		Fallback:        in.Fallback,
		ModelPolicies:   in.ModelPolicies,
	})
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, cons); err != nil {
		return nil, err
	}
	c.memoryCache.Set(cons.ID.String(), cons)
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, cons.GatewayID)
	return cons, nil
}

func validateAssociations(
	ctx context.Context,
	registryRepo registrydomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	gatewayID ids.GatewayID,
	registryIDs []ids.RegistryID,
	policyIDs []ids.PolicyID,
	authIDs []ids.AuthID,
	fallbackChain []ids.RegistryID,
) error {
	if err := validateRegistryIDsBelongToGateway(ctx, registryRepo, gatewayID, registryIDs); err != nil {
		return err
	}
	if err := validateRegistryIDsBelongToGateway(ctx, registryRepo, gatewayID, fallbackChain); err != nil {
		return err
	}
	if err := validatePolicyIDsBelongToGateway(ctx, policyRepo, gatewayID, policyIDs); err != nil {
		return err
	}
	return validateAuthIDsBelongToGateway(ctx, authRepo, gatewayID, authIDs)
}

func fallbackChainIDs(f *domain.Fallback) []ids.RegistryID {
	if f == nil {
		return nil
	}
	return []ids.RegistryID(f.Chain)
}

func validateRegistryIDsBelongToGateway(
	ctx context.Context,
	registryRepo registrydomain.Repository,
	gatewayID ids.GatewayID,
	idList []ids.RegistryID,
) error {
	if len(idList) == 0 {
		return nil
	}
	found, err := registryRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return err
	}
	foundIdx := make(map[ids.RegistryID]struct{}, len(found))
	for _, b := range found {
		foundIdx[b.ID] = struct{}{}
	}
	for _, id := range idList {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				registrydomain.ErrInvalidRegistryID, id, gatewayID)
		}
	}
	return nil
}

func validatePolicyIDsBelongToGateway(
	ctx context.Context,
	policyRepo policydomain.Repository,
	gatewayID ids.GatewayID,
	idList []ids.PolicyID,
) error {
	if len(idList) == 0 {
		return nil
	}
	found, err := policyRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return err
	}
	foundIdx := make(map[ids.PolicyID]struct{}, len(found))
	for _, p := range found {
		foundIdx[p.ID] = struct{}{}
	}
	for _, id := range idList {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				domain.ErrInvalidPolicyID, id, gatewayID)
		}
	}
	return nil
}

func validateAuthIDsBelongToGateway(
	ctx context.Context,
	authRepo authdomain.Repository,
	gatewayID ids.GatewayID,
	idList []ids.AuthID,
) error {
	if len(idList) == 0 {
		return nil
	}
	found, err := authRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return err
	}
	foundIdx := make(map[ids.AuthID]struct{}, len(found))
	for _, a := range found {
		foundIdx[a.ID] = struct{}{}
	}
	for _, id := range idList {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				domain.ErrInvalidAuthID, id, gatewayID)
		}
	}
	return nil
}
