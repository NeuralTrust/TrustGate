package consumer

import (
	"context"
	"fmt"
	"log/slog"

	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type CreateInput struct {
	GatewayID     uuid.UUID
	Name          string
	Type          domain.Type
	Path          string
	Paths         []string
	Methods       []string
	Headers       map[string]string
	StripPath     bool
	PreserveHost  bool
	Active        *bool
	Public        bool
	RetryAttempts int
	BackendIDs    []uuid.UUID
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=consumer_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Consumer, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	backendRepo backenddomain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	backendRepo backenddomain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:        repo,
		backendRepo: backendRepo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	if err := validateBackendIDsBelongToGateway(ctx, c.backendRepo, in.GatewayID, in.BackendIDs); err != nil {
		return nil, err
	}
	cons, err := domain.New(domain.CreateParams{
		GatewayID:     in.GatewayID,
		Name:          in.Name,
		Type:          in.Type,
		Path:          in.Path,
		Paths:         in.Paths,
		Methods:       in.Methods,
		Headers:       in.Headers,
		StripPath:     in.StripPath,
		PreserveHost:  in.PreserveHost,
		Active:        in.Active,
		Public:        in.Public,
		RetryAttempts: in.RetryAttempts,
		BackendIDs:    in.BackendIDs,
	})
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, cons); err != nil {
		return nil, err
	}
	c.memoryCache.Set(cons.ID.String(), cons)
	return cons, nil
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
	if len(found) == len(ids) {
		return nil
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
