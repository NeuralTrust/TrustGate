package gateway

import (
	"context"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
)

type contextKey string

const gatewayKey contextKey = "auth.gateway"

func WithGateway(ctx context.Context, gw *domain.Gateway) context.Context {
	return context.WithValue(ctx, gatewayKey, gw)
}

func FromContext(ctx context.Context) (*domain.Gateway, bool) {
	gw, ok := ctx.Value(gatewayKey).(*domain.Gateway)
	return gw, ok
}
