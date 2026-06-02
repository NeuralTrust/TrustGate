package backend

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

// publishBackendCacheInvalidation is best-effort: a publish error is logged, never
// returned, because the database write already succeeded.
func publishBackendCacheInvalidation(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID ids.GatewayID, backendID ids.BackendID,
) {
	evt := event.InvalidateBackendCacheEvent{
		GatewayID: gatewayID.String(),
		BackendID: backendID.String(),
	}
	if err := publisher.Publish(ctx, evt); err != nil {
		logger.Warn("failed to publish backend cache invalidation",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("backend_id", backendID.String()),
			slog.String("error", err.Error()),
		)
	}
}
