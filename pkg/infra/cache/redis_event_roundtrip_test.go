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
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/redis/go-redis/v9"
)

type snapshotDirtyRecorder struct{ hits chan struct{} }

func (s snapshotDirtyRecorder) OnEvent(context.Context, event.SnapshotDirtyEvent) error {
	select {
	case s.hits <- struct{}{}:
	default:
	}
	return nil
}

type gatewayDataRecorder struct{ ids chan string }

func (g gatewayDataRecorder) OnEvent(_ context.Context, ev event.InvalidateGatewayDataEvent) error {
	select {
	case g.ids <- ev.GatewayID:
	default:
	}
	return nil
}

// The admin-to-admin nudge that drives config-sync rides the same Redis channel
// and event registry as the cache invalidation event. This exercises the real
// publisher, envelope, registry lookup and typed dispatch end to end, so that
// pruning entries from the registry cannot silently break snapshot propagation.
func TestRedisEventBus_DeliversSnapshotDirtyAndGatewayDataEvents(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	c := &client{redisClient: rdb}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	listener := NewRedisEventListener(logger, c, event.GetEventsRegistry())

	dirty := snapshotDirtyRecorder{hits: make(chan struct{}, 1)}
	data := gatewayDataRecorder{ids: make(chan string, 1)}
	RegisterEventSubscriber[event.SnapshotDirtyEvent](listener, dirty)
	RegisterEventSubscriber[event.InvalidateGatewayDataEvent](listener, data)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Listen(ctx, channel.GatewayEventsChannel)

	publisher := NewRedisEventPublisher(c, channel.GatewayEventsChannel)
	const gatewayID = "212f3e18-6a41-4fcc-b1e6-189494d73f87"

	// Subscription setup races with the first publish, so keep nudging until
	// both events land or the deadline expires.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	var gotDirty bool
	var gotID string
	for gotDirty == false || gotID == "" {
		if err := publisher.Publish(ctx, event.SnapshotDirtyEvent{}); err != nil {
			t.Fatalf("publish snapshot dirty: %v", err)
		}
		if err := publisher.Publish(ctx, event.InvalidateGatewayDataEvent{GatewayID: gatewayID}); err != nil {
			t.Fatalf("publish gateway data invalidation: %v", err)
		}
		select {
		case <-dirty.hits:
			gotDirty = true
		case id := <-data.ids:
			gotID = id
		case <-tick.C:
		case <-deadline:
			t.Fatalf("events not dispatched: snapshot_dirty=%v gateway_data=%q", gotDirty, gotID)
		}
	}

	if gotID != gatewayID {
		t.Fatalf("gateway id = %q, want %q", gotID, gatewayID)
	}
}
