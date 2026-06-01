package consumer

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	"github.com/google/uuid"
)

func publishGatewayDataInvalidation(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID uuid.UUID,
) {
	evt := event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}
	if err := publisher.Publish(ctx, evt); err != nil {
		logger.Warn("failed to publish gateway data invalidation",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("error", err.Error()),
		)
	}
}
