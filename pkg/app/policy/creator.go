package policy

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID ids.GatewayID
	Name      string
	Plugins   domain.Plugins
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=policy_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Policy, error)
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
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Policy, error) {
	p, err := domain.NewPolicy(in.GatewayID, in.Name, in.Plugins)
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, p); err != nil {
		return nil, err
	}
	c.memoryCache.Set(p.ID.String(), p)
	return p, nil
}
