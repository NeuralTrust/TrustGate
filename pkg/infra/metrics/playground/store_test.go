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

package playground_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/playground"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T, cfg config.PlaygroundConfig) (*playground.Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return playground.NewStore(rdb, cfg, logger), mr, rdb
}

func playgroundRequest() *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Headers: map[string][]string{"X-AG-Playground-Token": {"a.jwt.token"}},
	}
}

func TestStore_SaveAndFindRoundTrip(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, mr, _ := newTestStore(t, cfg)

	evt := &events.Event{TraceID: "trace-123", GatewayID: "gw-1"}
	store.Save(context.Background(), playgroundRequest(), evt)

	got, err := store.Find(context.Background(), "trace-123")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "trace-123", got.TraceID)
	assert.Equal(t, "gw-1", got.GatewayID)

	ttl := mr.TTL("playground:trace:trace-123")
	assert.Greater(t, ttl, time.Duration(0), "stored trace must carry a TTL")
	assert.LessOrEqual(t, ttl, 10*time.Minute)
}

func TestStore_SaveSkipsNonPlaygroundRequest(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, _, _ := newTestStore(t, cfg)

	req := &infracontext.RequestContext{Headers: map[string][]string{"X-AG-Api-Key": {"k"}}}
	store.Save(context.Background(), req, &events.Event{TraceID: "trace-x"})

	got, err := store.Find(context.Background(), "trace-x")
	require.NoError(t, err)
	assert.Nil(t, got, "non-playground requests must not be stored")
}

func TestStore_SaveSkipsWhenDisabled(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: false, TraceStoreTTL: 10 * time.Minute}
	store, _, _ := newTestStore(t, cfg)

	store.Save(context.Background(), playgroundRequest(), &events.Event{TraceID: "trace-y"})

	got, err := store.Find(context.Background(), "trace-y")
	require.NoError(t, err)
	assert.Nil(t, got, "disabled store must not persist traces")
}

func TestStore_FindMissingReturnsNil(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, _, _ := newTestStore(t, cfg)

	got, err := store.Find(context.Background(), "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestStore_SaveSkipsEmptyTraceID(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, mr, _ := newTestStore(t, cfg)

	store.Save(context.Background(), playgroundRequest(), &events.Event{TraceID: ""})

	assert.Empty(t, mr.Keys(), "events without a TraceID must not be stored")
}
