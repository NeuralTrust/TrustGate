package cache

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

type EventPublisher interface {
	Publish(ctx context.Context, channel channel.Channel, ev event.Event) error
}
