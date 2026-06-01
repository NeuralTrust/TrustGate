package consumer

import (
	"context"

	"github.com/google/uuid"
)

// contextKey is a private type for context keys defined in this package, to
// avoid collisions with keys defined elsewhere (same pattern as metrics.CollectorKey).
type contextKey string

const (
	// GatewayIDKey carries the resolved gateway id (uuid.UUID) for the request.
	GatewayIDKey contextKey = "auth.gateway_id"
	// ConsumerDataKey carries the per-gateway *Data read model for the request.
	ConsumerDataKey contextKey = "auth.consumer_data"
)

func WithGatewayID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, GatewayIDKey, id)
}

func GatewayIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(GatewayIDKey).(uuid.UUID)
	return id, ok
}

func WithData(ctx context.Context, data *Data) context.Context {
	return context.WithValue(ctx, ConsumerDataKey, data)
}

func DataFromContext(ctx context.Context) (*Data, bool) {
	data, ok := ctx.Value(ConsumerDataKey).(*Data)
	return data, ok
}
