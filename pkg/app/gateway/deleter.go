package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=gateway_deleter_mock.go --case=underscore --with-expecter

// Deleter removes a gateway and invalidates the local TTL entry so
// subsequent reads in the same process see the removal immediately
// (without waiting for the TTL to expire). RUN-291 will replace this
// invalidation with a pub/sub event for the multi-replica case.
type Deleter interface {
	Delete(ctx context.Context, id uuid.UUID) error
}

type deleter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewDeleter(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Deleter {
	return &deleter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (d *deleter) Delete(ctx context.Context, id uuid.UUID) error {
	if err := d.repo.Delete(ctx, id); err != nil {
		return err
	}
	d.memoryCache.Delete(id.String())
	return nil
}
