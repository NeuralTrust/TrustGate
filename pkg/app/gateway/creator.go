// Package gateway is the application-layer use cases that orchestrate
// the gateway aggregate. One file per use case (interface + impl +
// generate directive) — see .agents/AGENT.md.
package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter

// CreateInput is the boundary input for Creator. The HTTP request DTO
// (pkg/api/handler/http/request) maps onto this in Phase 3; the use
// case stays free of transport concerns.
type CreateInput struct {
	Name        string
	Description string
}

// Creator creates a new gateway and pre-warms the local TTL cache so
// the immediate read-after-write hits memory.
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Gateway, error)
}

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

// NewCreator wires a Creator that persists through the given repository
// and primes the gateway namespace of the shared TTL cache manager.
func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Gateway, error) {
	g, err := domain.New(in.Name, in.Description)
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, g); err != nil {
		return nil, err
	}
	c.memoryCache.Set(g.ID.String(), g)
	return g, nil
}
