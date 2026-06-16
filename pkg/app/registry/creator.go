package registry

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID   ids.GatewayID
	Name        string
	Type        domain.Type
	Enabled     *bool
	Description string
	LLMTarget   *domain.LLMTarget
	MCPTarget   *domain.MCPTarget
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
	var b *domain.Registry
	var err error
	if in.Type == domain.TypeMCP {
		b, err = domain.NewMCPRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.MCPTarget,
		)
	} else {
		b, err = domain.NewLLMRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.LLMTarget,
		)
	}
	if err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		b.Enabled = *in.Enabled
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	c.memoryCache.Set(b.ID.String(), b)
	return b, nil
}
