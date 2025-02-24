package cache

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

type redisEventPublisher struct {
	cache *cache.Cache
}

func NewRedisEventPublisher(cache *cache.Cache) EventPublisher {
	return &redisEventPublisher{
		cache: cache,
	}
}

func (p *redisEventPublisher) Publish(ctx context.Context, channel channel.Channel, ev event.Event) error {
	t := reflect.TypeOf(ev)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
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
	return p.cache.Client().Publish(ctx, string(channel), data).Err()
}
