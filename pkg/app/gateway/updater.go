package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=gateway_updater_mock.go --case=underscore --with-expecter

// UpdateInput models a full-replacement PUT-style update. The handler
// rejects requests missing required fields before reaching here.
type UpdateInput struct {
	ID          uuid.UUID
	Name        string
	Description string
}

// Updater loads, mutates, and persists a gateway, refreshing the local
// TTL cache so the next read sees the post-write state immediately.
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error)
}

type updater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewUpdater(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Updater {
	return &updater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error) {
	g, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if err := g.Rename(in.Name); err != nil {
		return nil, err
	}
	if err := g.SetDescription(in.Description); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, g); err != nil {
		return nil, err
	}
	u.memoryCache.Set(g.ID.String(), g)
	return g, nil
}
