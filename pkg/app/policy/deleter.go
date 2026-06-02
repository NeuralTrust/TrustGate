package policy

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=policy_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error
}

var _ Deleter = (*deleter)(nil)

type deleter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewDeleter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Deleter {
	return &deleter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (d *deleter) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error {
	existing, err := d.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if existing.GatewayID != gatewayID {
		return domain.ErrNotFound
	}
	if err := d.repo.Delete(ctx, id); err != nil {
		return err
	}
	d.memoryCache.Delete(id.String())
	publishGatewayDataInvalidation(ctx, d.publisher, d.logger, existing.GatewayID)
	return nil
}
