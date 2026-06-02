package consumer

import (
	"context"
	"fmt"
	"log/slog"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            domain.Type
	Path            string
	Algorithm       string
	EmbeddingConfig *backenddomain.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	BackendIDs      []ids.BackendID
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
	repo        domain.Repository
	backendRepo backenddomain.Repository
	policyRepo  policydomain.Repository
	authRepo    authdomain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	backendRepo backenddomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:        repo,
		backendRepo: backendRepo,
		policyRepo:  policyRepo,
		authRepo:    authRepo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	if err := validateAssociations(ctx, c.backendRepo, c.policyRepo, c.authRepo,
		in.GatewayID, in.BackendIDs, in.PolicyIDs, in.AuthIDs, fallbackChainIDs(in.Fallback)); err != nil {
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
		BackendIDs:      in.BackendIDs,
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
	backendRepo backenddomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	gatewayID ids.GatewayID,
	backendIDs []ids.BackendID,
	policyIDs []ids.PolicyID,
	authIDs []ids.AuthID,
	fallbackChain []ids.BackendID,
) error {
	if err := validateBackendIDsBelongToGateway(ctx, backendRepo, gatewayID, backendIDs); err != nil {
		return err
	}
	if err := validateBackendIDsBelongToGateway(ctx, backendRepo, gatewayID, fallbackChain); err != nil {
		return err
	}
	if err := validatePolicyIDsBelongToGateway(ctx, policyRepo, gatewayID, policyIDs); err != nil {
		return err
	}
	return validateAuthIDsBelongToGateway(ctx, authRepo, gatewayID, authIDs)
}

func fallbackChainIDs(f *domain.Fallback) []ids.BackendID {
	if f == nil {
		return nil
	}
	return []ids.BackendID(f.Chain)
}

func validateBackendIDsBelongToGateway(
	ctx context.Context,
	backendRepo backenddomain.Repository,
	gatewayID ids.GatewayID,
	idList []ids.BackendID,
) error {
	if len(idList) == 0 {
		return nil
	}
	found, err := backendRepo.FindByIDs(ctx, gatewayID, idList)
	if err != nil {
		return err
	}
	foundIdx := make(map[ids.BackendID]struct{}, len(found))
	for _, b := range found {
		foundIdx[b.ID] = struct{}{}
	}
	for _, id := range idList {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				backenddomain.ErrInvalidBackendID, id, gatewayID)
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
