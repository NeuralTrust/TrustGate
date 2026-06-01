package gateway

import (
	"context"
	"log/slog"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type UpdateInput struct {
	ID              uuid.UUID
	Name            string
	Status          string
	Telemetry       *telemetry.Telemetry
	ClientTLSConfig domain.ClientTLSConfig
	SessionConfig   *domain.SessionConfig
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=gateway_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error)
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
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error) {
	g, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	g.Name = in.Name
	g.Status = in.Status
	g.Telemetry = in.Telemetry
	g.ClientTLSConfig = in.ClientTLSConfig
	g.SessionConfig = in.SessionConfig
	g.UpdatedAt = time.Now().UTC()
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, g); err != nil {
		return nil, err
	}
	u.memoryCache.Set(g.ID.String(), g)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, g.ID)
	return g, nil
}
