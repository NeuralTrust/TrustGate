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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/playground"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

func TestStore_SavePushesPlaygroundTraceToControlPlane(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := config.PlaygroundConfig{
		TraceStoreEnabled: true,
		TraceStoreTTL:     10 * time.Minute,
		TracePushURL:      srv.URL + "/", // trailing slash must not double up
		TracePushToken:    "push-token",
	}
	store, _, _ := newTestStore(t, cfg)

	store.Save(context.Background(), playgroundRequest(), &events.Event{TraceID: "trace-push", GatewayID: "gw-1"})

	assert.Equal(t, http.MethodPut, gotMethod)
	assert.Equal(t, "/v1/playground/traces/trace-push", gotPath)
	assert.Equal(t, "Bearer push-token", gotAuth)
	var pushed events.Event
	require.NoError(t, json.Unmarshal(gotBody, &pushed))
	assert.Equal(t, "trace-push", pushed.TraceID)
	assert.Equal(t, "gw-1", pushed.GatewayID)

	// The local store keeps its copy too.
	got, err := store.Find(context.Background(), "trace-push")
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestStore_SaveDoesNotPushNonPlaygroundRequests(t *testing.T) {
	pushed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pushed = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := config.PlaygroundConfig{
		TraceStoreEnabled: true,
		TraceStoreTTL:     10 * time.Minute,
		TracePushURL:      srv.URL,
	}
	store, _, _ := newTestStore(t, cfg)

	req := &infracontext.RequestContext{Headers: map[string][]string{"X-AG-Api-Key": {"k"}}}
	store.Save(context.Background(), req, &events.Event{TraceID: "trace-real"})

	assert.False(t, pushed, "regular traffic must never be pushed across the boundary")
}

func TestStore_SaveSurvivesPushFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.PlaygroundConfig{
		TraceStoreEnabled: true,
		TraceStoreTTL:     10 * time.Minute,
		TracePushURL:      srv.URL,
	}
	store, _, _ := newTestStore(t, cfg)

	store.Save(context.Background(), playgroundRequest(), &events.Event{TraceID: "trace-rejected"})

	got, err := store.Find(context.Background(), "trace-rejected")
	require.NoError(t, err)
	require.NotNil(t, got, "a rejected push must not lose the local copy")
}

func TestStore_PutStoresWithoutPlaygroundHeader(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, mr, _ := newTestStore(t, cfg)

	require.NoError(t, store.Put(context.Background(), &events.Event{TraceID: "trace-put", GatewayID: "gw-2"}))

	got, err := store.Find(context.Background(), "trace-put")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "gw-2", got.GatewayID)
	assert.Greater(t, mr.TTL("playground:trace:trace-put"), time.Duration(0))
}

func TestStore_PutRejectsMissingTraceID(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: true, TraceStoreTTL: 10 * time.Minute}
	store, _, _ := newTestStore(t, cfg)

	assert.Error(t, store.Put(context.Background(), &events.Event{}))
	assert.Error(t, store.Put(context.Background(), nil))
}

func TestStore_PutRejectsWhenDisabled(t *testing.T) {
	cfg := config.PlaygroundConfig{TraceStoreEnabled: false, TraceStoreTTL: 10 * time.Minute}
	store, _, _ := newTestStore(t, cfg)

	assert.Error(t, store.Put(context.Background(), &events.Event{TraceID: "t"}))
}
