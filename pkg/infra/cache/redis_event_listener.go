// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

var _ EventListener = (*redisEventListener)(nil)

type redisEventListener struct {
	logger      *slog.Logger
	cache       Client
	mu          sync.RWMutex
	subscribers map[reflect.Type]EventDispatchFunc
	registry    map[string]reflect.Type
}

func NewRedisEventListener(
	logger *slog.Logger,
	cache Client,
	registry map[string]reflect.Type,
) EventListener {
	return &redisEventListener{
		logger:      logger,
		cache:       cache,
		subscribers: make(map[reflect.Type]EventDispatchFunc),
		registry:    registry,
	}
}

func RegisterEventSubscriber[T event.Event](pub EventListener, subscriber EventSubscriber[T]) {
	var evt T
	eventType := reflect.TypeOf(evt)
	pub.Register(eventType, func(ctx context.Context, raw any) error {
		ev, ok := raw.(T)
		if !ok {
			return nil
		}
		return subscriber.OnEvent(ctx, ev)
	})
}

func (r *redisEventListener) Register(eventType reflect.Type, dispatch EventDispatchFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscribers[eventType] = dispatch
}

func (r *redisEventListener) Listen(ctx context.Context, channels ...channel.Channel) {
	channelNames := make([]string, 0, len(channels))
	for _, ch := range channels {
		channelNames = append(channelNames, string(ch))
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info(bootlog.RedisPubSubShuttingDown)
			return
		default:
		}

		r.listenWithReconnect(ctx, channelNames)

		if ctx.Err() != nil {
			return
		}

		r.logger.Warn("redis pubsub disconnected, reconnecting in 1s...")
		time.Sleep(time.Second)
	}
}

func (r *redisEventListener) listenWithReconnect(ctx context.Context, channelNames []string) {
	pubSub := r.cache.RedisClient().Subscribe(ctx, channelNames...)
	defer func() { _ = pubSub.Close() }()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = pubSub.Close()
		case <-stop:
		}
	}()

	r.logger.Debug(bootlog.RedisPubSubConnected, slog.Any("channels", channelNames))

	for msg := range pubSub.Channel() {
		select {
		case <-ctx.Done():
			return
		default:
			r.handleMessage(ctx, msg.Payload)
		}
	}
}

func (r *redisEventListener) handleMessage(ctx context.Context, payload string) {
	var envelope RedisMessage
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		r.logger.Error("error decoding redis message", slog.String("error", err.Error()))
		return
	}
	r.logger.Debug("received redis message", slog.String("event_type", envelope.Type))

	concreteType, err := r.getEvent(envelope.Type)
	if err != nil {
		r.logger.Error("error getting event type", slog.String("error", err.Error()))
		return
	}

	eventPtr := reflect.New(concreteType)
	if err := json.Unmarshal(envelope.Event, eventPtr.Interface()); err != nil {
		r.logger.Error("error unmarshalling event data into concrete type", slog.String("error", err.Error()))
		return
	}
	concreteEvent := eventPtr.Elem().Interface()

	r.notifySubscribers(ctx, concreteType, concreteEvent)
}

func (r *redisEventListener) notifySubscribers(ctx context.Context, eventType reflect.Type, concreteEvent any) {
	r.mu.RLock()
	dispatch, ok := r.subscribers[eventType]
	r.mu.RUnlock()
	if !ok {
		return
	}
	if err := dispatch(ctx, concreteEvent); err != nil {
		r.logger.Error("error executing subscriber",
			slog.String("event_type", eventType.String()),
			slog.String("error", err.Error()),
		)
	}
}

func (r *redisEventListener) getEvent(eventType string) (reflect.Type, error) {
	concreteType, ok := r.registry[eventType]
	if !ok {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}
	return concreteType, nil
}
