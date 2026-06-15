package auth

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID ids.GatewayID
	Name      string
	Type      domain.Type
	Enabled   bool
	Config    domain.Config
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=auth_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Auth, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	logger      *slog.Logger
}

func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Auth, error) {
	a, err := c.build(in)
	if err != nil {
		return nil, err
	}
	if err := ensureNoOAuth2Conflict(ctx, c.repo, a); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, a); err != nil {
		return nil, err
	}
	c.memoryCache.Set(a.ID.String(), a)
	if a.KeyHash != "" {
		c.keyCache.Set(a.KeyHash, a)
	}
	return a, nil
}

func (c *creator) build(in CreateInput) (*domain.Auth, error) {
	if in.Type == domain.TypeAPIKey {
		return domain.NewAPIKeyAuth(in.GatewayID, in.Name, in.Enabled)
	}
	return domain.NewAuth(in.GatewayID, in.Name, in.Type, in.Enabled, in.Config)
}
