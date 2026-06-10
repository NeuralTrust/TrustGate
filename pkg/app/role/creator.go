package role

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID   ids.GatewayID
	Name        string
	McpPolicies json.RawMessage
	IDPMapping  json.RawMessage
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=role_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Role, error)
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
		memoryCache: manager.GetTTLMap(cache.RoleTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Role, error) {
	role, err := domain.New(domain.CreateParams{
		GatewayID:   in.GatewayID,
		Name:        in.Name,
		McpPolicies: in.McpPolicies,
		IDPMapping:  in.IDPMapping,
	})
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, role); err != nil {
		return nil, err
	}
	c.memoryCache.Set(role.ID.String(), role)
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, role.GatewayID)
	return role, nil
}
