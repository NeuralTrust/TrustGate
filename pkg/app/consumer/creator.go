package consumer

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID ids.GatewayID
	Name      string
	Type      domain.Type
	Path      string
	Headers   map[string]string
	Active    *bool
	LLM       *domain.LLMPolicy
	MCP       *domain.MCPPolicy
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=consumer_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Consumer, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	cons, err := domain.New(domain.CreateParams{
		GatewayID: in.GatewayID,
		Name:      in.Name,
		Type:      in.Type,
		Path:      in.Path,
		Headers:   in.Headers,
		Active:    in.Active,
		LLM:       in.LLM,
		MCP:       in.MCP,
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
