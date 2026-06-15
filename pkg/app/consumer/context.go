package consumer

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type contextKey string

const (
	GatewayIDKey    contextKey = "auth.gateway_id"
	ConsumerDataKey contextKey = "auth.consumer_data"
	AuthIDKey       contextKey = "auth.auth_id"
	ConsumerKey     contextKey = "auth.consumer"
)

func WithGatewayID(ctx context.Context, id ids.GatewayID) context.Context {
	return context.WithValue(ctx, GatewayIDKey, id)
}

func GatewayIDFromContext(ctx context.Context) (ids.GatewayID, bool) {
	id, ok := ctx.Value(GatewayIDKey).(ids.GatewayID)
	return id, ok
}

func WithAuthID(ctx context.Context, id ids.AuthID) context.Context {
	return context.WithValue(ctx, AuthIDKey, id)
}

func AuthIDFromContext(ctx context.Context) (ids.AuthID, bool) {
	id, ok := ctx.Value(AuthIDKey).(ids.AuthID)
	return id, ok
}

func WithData(ctx context.Context, data *Data) context.Context {
	return context.WithValue(ctx, ConsumerDataKey, data)
}

func DataFromContext(ctx context.Context) (*Data, bool) {
	data, ok := ctx.Value(ConsumerDataKey).(*Data)
	return data, ok
}

func WithConsumer(ctx context.Context, consumer *RoutableConsumer) context.Context {
	return context.WithValue(ctx, ConsumerKey, consumer)
}

func ConsumerFromContext(ctx context.Context) (*RoutableConsumer, bool) {
	consumer, ok := ctx.Value(ConsumerKey).(*RoutableConsumer)
	return consumer, ok && consumer != nil
}
