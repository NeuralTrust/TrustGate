package consumer

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/google/uuid"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=consumer_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, id uuid.UUID) error
}

var _ Deleter = (*deleter)(nil)

type deleter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewDeleter(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Deleter {
	return &deleter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
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
