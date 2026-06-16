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
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/channel"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ EventListener = (*redisEventListener)(nil)

type redisEventListener struct {
	logger      *slog.Logger
	cache       Client
	subscribers map[reflect.Type]interface{}
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
		subscribers: make(map[reflect.Type]interface{}),
		registry:    registry,
	}
}

func RegisterEventSubscriber[T event.Event](pub EventListener, subscriber EventSubscriber[T]) {
	var evt T
	eventType := reflect.TypeOf(evt)
	pub.Register(eventType, subscriber)
}

func (r *redisEventListener) Register(eventType reflect.Type, subscriber interface{}) {
	r.subscribers[eventType] = subscriber
}

func (r *redisEventListener) Listen(ctx context.Context, channels ...channel.Channel) {
	channelNames := make([]string, 0, len(channels))
	for _, ch := range channels {
		channelNames = append(channelNames, string(ch))
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("redis pubsub listener shutting down")
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

	r.logger.Debug("redis pubsub connected", slog.Any("channels", channelNames))

	go func() {
		<-ctx.Done()
		_ = pubSub.Close()
	}()

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
	r.logger.Info("received redis message", slog.String("payload", payload))
	var envelope RedisMessage
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		r.logger.Error("error decoding redis message", slog.String("error", err.Error()))
		return
	}

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

	r.notifySubscribers(ctx, concreteEvent)
}

func (r *redisEventListener) notifySubscribers(ctx context.Context, concreteEvent interface{}) {
	for _, sub := range r.subscribers {
		sVal := reflect.ValueOf(sub)
		method := sVal.MethodByName("OnEvent")
		if !method.IsValid() {
			r.logger.Debug("subscriber does not implement OnEvent")
			continue
		}

		expectedType := method.Type().In(1)
		eventValue := reflect.ValueOf(concreteEvent)
		if !eventValue.Type().AssignableTo(expectedType) {
			continue
		}

		results := method.Call([]reflect.Value{reflect.ValueOf(ctx), eventValue})
		if len(results) > 0 && !results[0].IsNil() {
			if err, ok := results[0].Interface().(error); ok {
				r.logger.Error("error executing subscriber",
					slog.Any("event", concreteEvent),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func (r *redisEventListener) getEvent(eventType string) (reflect.Type, error) {
	concreteType, ok := r.registry[eventType]
	if !ok {
		return nil, fmt.Errorf("unknown event type: %s", eventType)
	}
	return concreteType, nil
}
