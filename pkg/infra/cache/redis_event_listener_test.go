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
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
)

type dispatchTestEvent struct{ ID string }

func (dispatchTestEvent) Type() string { return "dispatchTestEvent" }

type otherTestEvent struct{}

func (otherTestEvent) Type() string { return "otherTestEvent" }

type funcSubscriber struct {
	fn func(context.Context, dispatchTestEvent) error
}

func (s funcSubscriber) OnEvent(ctx context.Context, ev dispatchTestEvent) error {
	return s.fn(ctx, ev)
}

func newTestListener() *redisEventListener {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRedisEventListener(logger, nil, nil).(*redisEventListener)
}

func TestRedisEventListener_TypedDispatchRoutesByType(t *testing.T) {
	t.Parallel()
	l := newTestListener()
	got := make(chan string, 1)
	RegisterEventSubscriber[dispatchTestEvent](l, funcSubscriber{fn: func(_ context.Context, ev dispatchTestEvent) error {
		got <- ev.ID
		return nil
	}})

	l.notifySubscribers(context.Background(), reflect.TypeOf(otherTestEvent{}), otherTestEvent{})
	l.notifySubscribers(context.Background(), reflect.TypeOf(dispatchTestEvent{}), dispatchTestEvent{ID: "abc"})

	select {
	case id := <-got:
		if id != "abc" {
			t.Fatalf("dispatched id = %q, want abc", id)
		}
	default:
		t.Fatal("subscriber was not invoked for its event type")
	}
}

func TestRedisEventListener_ConcurrentRegisterAndDispatch(t *testing.T) {
	t.Parallel()
	l := newTestListener()
	RegisterEventSubscriber[dispatchTestEvent](l, funcSubscriber{fn: func(context.Context, dispatchTestEvent) error {
		return nil
	}})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			l.Register(reflect.TypeOf(otherTestEvent{}), func(context.Context, any) error { return nil })
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			l.notifySubscribers(context.Background(), reflect.TypeOf(dispatchTestEvent{}), dispatchTestEvent{ID: "x"})
		}
	}()
	wg.Wait()
}
