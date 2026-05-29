package consumer

import (
	"context"
	"log/slog"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type UpdateInput struct {
	ID         uuid.UUID
	GatewayID  uuid.UUID
	Name       string
	Type       domain.Type
	Headers    map[string]string
	Active     *bool
	BackendIDs []uuid.UUID
	PolicyIDs  []uuid.UUID
	AuthIDs    []uuid.UUID
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	backendRepo backenddomain.Repository
	policyRepo  policydomain.Repository
	authRepo    authdomain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	backendRepo backenddomain.Repository,
	policyRepo policydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		backendRepo: backendRepo,
		policyRepo:  policyRepo,
		authRepo:    authRepo,
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
	if in.GatewayID != uuid.Nil && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	if err := validateAssociations(ctx, u.backendRepo, u.policyRepo, u.authRepo,
		existing.GatewayID, in.BackendIDs, in.PolicyIDs, in.AuthIDs); err != nil {
		return nil, err
	}
	existing.Name = in.Name
	if in.Type != "" {
		existing.Type = in.Type
	}
	existing.Headers = in.Headers
	if in.Active != nil {
		existing.Active = *in.Active
	}
	existing.BackendIDs = in.BackendIDs
	existing.PolicyIDs = in.PolicyIDs
	existing.AuthIDs = in.AuthIDs
	existing.UpdatedAt = time.Now().UTC()
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
