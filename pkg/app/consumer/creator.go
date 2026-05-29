package consumer

import (
	"context"
	"fmt"
	"log/slog"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type CreateInput struct {
	GatewayID  uuid.UUID
	Name       string
	Type       domain.Type
	Headers    map[string]string
	Active     *bool
	BackendIDs []uuid.UUID
	PolicyIDs  []uuid.UUID
	AuthIDs    []uuid.UUID
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
		in.GatewayID, in.BackendIDs, in.PolicyIDs, in.AuthIDs); err != nil {
		return nil, err
	}
	cons, err := domain.New(domain.CreateParams{
		GatewayID:  in.GatewayID,
		Name:       in.Name,
		Type:       in.Type,
		Headers:    in.Headers,
		Active:     in.Active,
		BackendIDs: in.BackendIDs,
		PolicyIDs:  in.PolicyIDs,
		AuthIDs:    in.AuthIDs,
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
	gatewayID uuid.UUID,
	backendIDs, policyIDs, authIDs []uuid.UUID,
) error {
	if err := validateBackendIDsBelongToGateway(ctx, backendRepo, gatewayID, backendIDs); err != nil {
		return err
	}
	if err := validatePolicyIDsBelongToGateway(ctx, policyRepo, gatewayID, policyIDs); err != nil {
		return err
	}
	return validateAuthIDsBelongToGateway(ctx, authRepo, gatewayID, authIDs)
}

func validateBackendIDsBelongToGateway(
	ctx context.Context,
	backendRepo backenddomain.Repository,
	gatewayID uuid.UUID,
	ids []uuid.UUID,
) error {
	if len(ids) == 0 {
		return nil
	}
	found, err := backendRepo.FindByIDs(ctx, gatewayID, ids)
	if err != nil {
		return err
	}
	foundIdx := make(map[uuid.UUID]struct{}, len(found))
	for _, b := range found {
		foundIdx[b.ID] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				domain.ErrInvalidBackendID, id, gatewayID)
		}
	}
	return nil
}

func validatePolicyIDsBelongToGateway(
	ctx context.Context,
	policyRepo policydomain.Repository,
	gatewayID uuid.UUID,
	ids []uuid.UUID,
) error {
	if len(ids) == 0 {
		return nil
	}
	found, err := policyRepo.FindByIDs(ctx, gatewayID, ids)
	if err != nil {
		return err
	}
	foundIdx := make(map[uuid.UUID]struct{}, len(found))
	for _, p := range found {
		foundIdx[p.ID] = struct{}{}
	}
	for _, id := range ids {
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
	gatewayID uuid.UUID,
	ids []uuid.UUID,
) error {
	if len(ids) == 0 {
		return nil
	}
	found, err := authRepo.FindByIDs(ctx, gatewayID, ids)
	if err != nil {
		return err
	}
	foundIdx := make(map[uuid.UUID]struct{}, len(found))
	for _, a := range found {
		foundIdx[a.ID] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := foundIdx[id]; !ok {
			return fmt.Errorf("%w: %s not found in gateway %s",
				domain.ErrInvalidAuthID, id, gatewayID)
		}
	}
	return nil
}
