// Package gateway is the application-layer use cases that orchestrate
// the gateway aggregate. One file per use case (interface + impl +
// generate directive) — see .agents/AGENT.md.
package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	Name            string
	Slug            string
	Telemetry       *telemetry.Telemetry
	ClientTLSConfig domain.ClientTLSConfig
	SessionConfig   *domain.SessionConfig
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Gateway, error)
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
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Gateway, error) {
	g, err := domain.New(in.Name, in.Slug)
	if err != nil {
		return nil, err
	}
	g.Telemetry = in.Telemetry
	g.ClientTLSConfig = in.ClientTLSConfig
	g.SessionConfig = in.SessionConfig
	if g.SessionConfig == nil {
		g.SessionConfig = domain.DefaultSessionConfig()
	}
	if err := c.repo.Save(ctx, g); err != nil {
		return nil, err
	}
	setGatewayCache(c.memoryCache, g)
	return g, nil
}
