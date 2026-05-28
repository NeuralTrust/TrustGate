package consumer

import (
	"context"
	"log/slog"
	"time"

	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type UpdateInput struct {
	ID            uuid.UUID
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

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	backendRepo backenddomain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	backendRepo backenddomain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		backendRepo: backendRepo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
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
	if err := validateBackendIDsBelongToGateway(ctx, u.backendRepo, existing.GatewayID, in.BackendIDs); err != nil {
		return nil, err
	}
	existing.Name = in.Name
	if in.Type != "" {
		existing.Type = in.Type
	}
	existing.Path = in.Path
	existing.Paths = in.Paths
	existing.Methods = in.Methods
	existing.Headers = in.Headers
	existing.StripPath = in.StripPath
	existing.PreserveHost = in.PreserveHost
	if in.Active != nil {
		existing.Active = *in.Active
	}
	existing.Public = in.Public
	existing.RetryAttempts = in.RetryAttempts
	existing.BackendIDs = in.BackendIDs
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	return existing, nil
}
