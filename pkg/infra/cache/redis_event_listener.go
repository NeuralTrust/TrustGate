package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type redisEventListener struct {
	logger      *logrus.Logger
	cache       cache.Cache
	subscribers map[reflect.Type]interface{}
	registry    map[string]reflect.Type
}

func NewRedisEventListener(
	logger *logrus.Logger,
	cache cache.Cache,
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
	var channelNames []string
	for _, ch := range channels {
		channelNames = append(channelNames, string(ch))
	}

	pubSub := r.cache.Client().Subscribe(ctx, channelNames...)
	defer func() { _ = pubSub.Close() }()

	for msg := range pubSub.Channel() {
		var envelope RedisMessage
		if err := json.Unmarshal([]byte(msg.Payload), &envelope); err != nil {
			r.logger.WithError(err).Error("error decoding redis message")
			continue
		}
		concreteType, err := r.getEvent(envelope.Type)
		if err != nil {
			r.logger.WithError(err).Error("error getting event type")
			continue
		}

		eventPtr := reflect.New(concreteType)
		if err := json.Unmarshal(envelope.Event, eventPtr.Interface()); err != nil {
			r.logger.WithError(err).Error("error unmarshalling event data into concrete type")
			continue
		}
		concreteEvent := eventPtr.Elem().Interface()

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
					r.logger.WithError(err).Errorf("error executing subscriber for event %v", concreteEvent)
				}
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
