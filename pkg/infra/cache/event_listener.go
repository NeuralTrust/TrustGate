package cache

import (
	"context"
	"reflect"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/channel"
)

type EventListener interface {
	Listen(ctx context.Context, channels ...channel.Channel)
	Register(eventType reflect.Type, subscriber interface{})
}
