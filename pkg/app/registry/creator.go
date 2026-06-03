package registry

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID       ids.GatewayID
	Name            string
	Provider        string
	ProviderOptions map[string]any
	Description     string
	Weight          int
	Auth            *domain.TargetAuth
	HealthChecks    *domain.HealthChecks
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=registry_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Registry, error)
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
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Registry, error) {
	b, err := domain.NewRegistry(
		in.GatewayID,
		in.Name,
		in.Provider,
		in.ProviderOptions,
		in.Description,
		in.Weight,
		in.Auth,
		in.HealthChecks,
	)
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	c.memoryCache.Set(b.ID.String(), b)
	return b, nil
}
