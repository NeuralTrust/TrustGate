package cache

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

//go:generate mockery --name=EventPublisher --dir=. --output=./mocks --filename=event_publisher_mock.go --case=underscore --with-expecter

type EventPublisher interface {
	Publish(ctx context.Context, channel channel.Channel, ev event.Event) error
}
