package gateway

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Deleter --dir=. --output=../../../mocks --filename=gateway_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, id uuid.UUID) error
}

type deleter struct {
	logger    *logrus.Logger
	repo      domainGateway.Repository
	publisher infraCache.EventPublisher
}

func NewDeleter(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	publisher infraCache.EventPublisher,
) Deleter {
	return &deleter{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

func (d *deleter) Delete(ctx context.Context, id uuid.UUID) error {
	if err := d.repo.Delete(id); err != nil {
		if domain.IsNotFoundError(err) {
			return err
		}
		d.logger.WithError(err).Error("Failed to delete gateway")
		return err
	}

	if err := d.publisher.Publish(
		ctx,
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{
			GatewayID: id.String(),
		},
	); err != nil {
		d.logger.WithError(err).Error("failed to publish gateway event")
	}

	return nil
}
