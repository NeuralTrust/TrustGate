package backend

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

type CreateInput struct {
	GatewayID       uuid.UUID
	Name            string
	Algorithm       string
	Targets         domain.Targets
	EmbeddingConfig *domain.EmbeddingConfig
	HealthChecks    *domain.HealthChecks
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=backend_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Backend, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.BackendTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Backend, error) {
	b, err := domain.New(domain.CreateParams{
		GatewayID:       in.GatewayID,
		Name:            in.Name,
		Algorithm:       in.Algorithm,
		Targets:         in.Targets,
		EmbeddingConfig: in.EmbeddingConfig,
		HealthChecks:    in.HealthChecks,
	})
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	c.memoryCache.Set(b.ID.String(), b)
	return b, nil
}
