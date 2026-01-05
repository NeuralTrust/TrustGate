package cache

import (
	"context"
	"encoding/json"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

type RedisPublisherInitializer func(cache Client, channel channel.Channel) EventPublisher

type redisEventPublisher struct {
	cache   Client
	channel channel.Channel
}

func NewRedisEventPublisher(cache Client, channel channel.Channel) EventPublisher {
	return &redisEventPublisher{
		cache:   cache,
		channel: channel,
	}
}

func (p *redisEventPublisher) Publish(ctx context.Context, ev event.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	envelope := RedisMessage{
		Type:  ev.Type(),
		Event: b,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return p.cache.RedisClient().Publish(ctx, string(p.channel), data).Err()
}
