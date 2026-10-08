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

package loadbalancer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/complexity"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/strategies"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newBackend(t *testing.T, name string) *registry.Registry {
	t.Helper()
	b, err := registry.NewLLMRegistry(
		ids.New[ids.GatewayKind](),
		name,
		"",
		&registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth("sk-1")},
	)
	if err != nil {
		t.Fatalf("NewLLMRegistry error: %v", err)
	}
	return b
}

func TestLoadBalancer_NextRoute_SkipsUnhealthyViaMGet(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().RedisClient().Return(rdb).Maybe()

	unhealthy := newBackend(t, "unhealthy")
	healthy := newBackend(t, "healthy")

	if err := mr.Set(fmt.Sprintf("lb:health:%s", unhealthy.ID.String()), `{"Healthy":false}`); err != nil {
		t.Fatalf("seed unhealthy status: %v", err)
	}

	lb, err := loadbalancer.NewLoadBalancer(loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil), loadbalancer.Pool{
		ID: uuid.New().String(),
		Routes: []routingdomain.Route{
			routingdomain.RouteForRegistry(unhealthy),
			routingdomain.RouteForRegistry(healthy),
		},
		Algorithm: loadbalancer.AlgorithmRoundRobin,
	}, newTestLogger(), cacheClient)
	if err != nil {
		t.Fatalf("NewLoadBalancer error: %v", err)
	}
	t.Cleanup(lb.Close)

	req := &infracontext.RequestContext{}
	for i := 0; i < 4; i++ {
		got, nerr := lb.NextRoute(context.Background(), req, nil)
		if nerr != nil {
			t.Fatalf("NextRoute error: %v", nerr)
		}
		if got.RegistryID() != healthy.ID {
			t.Fatalf("NextRoute returned %q, want the healthy backend", got.Registry.Name)
		}
	}
}

func TestLoadBalancer_NextRoute_HealthIsSharedByRoutesOfOneRegistry(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().RedisClient().Return(rdb).Maybe()

	shared := newBackend(t, "shared")
	if err := mr.Set(fmt.Sprintf("lb:health:%s", shared.ID.String()), `{"Healthy":false}`); err != nil {
		t.Fatalf("seed unhealthy status: %v", err)
	}

	lb, err := loadbalancer.NewLoadBalancer(loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil), loadbalancer.Pool{
		ID: uuid.New().String(),
		Routes: []routingdomain.Route{
			{Registry: shared, Model: "gpt-4o-mini", Weight: 1},
			{Registry: shared, Model: "gpt-5", Weight: 1},
		},
		Algorithm: loadbalancer.AlgorithmRoundRobin,
	}, newTestLogger(), cacheClient)
	if err != nil {
		t.Fatalf("NewLoadBalancer error: %v", err)
	}
	t.Cleanup(lb.Close)

	got, nerr := lb.NextRoute(context.Background(), &infracontext.RequestContext{}, nil)
	if nerr != nil {
		t.Fatalf("NextRoute error: %v", nerr)
	}
	if got == nil || got.RegistryID() != shared.ID {
		t.Fatalf("an all-unhealthy pool must still yield its last candidate, got %+v", got)
	}
}

func TestSmartRoutingHealthRecoveryPreservesCommitmentAndExclusions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cache := cachemocks.NewClient(t)
	cache.EXPECT().RedisClient().Return(client).Maybe()
	low, high := newBackend(t, "low"), newBackend(t, "high")
	high.LLMTarget.HealthChecks = &registry.HealthChecks{Passive: true, Threshold: 1, Interval: 60}
	routes := []routingdomain.Route{{Registry: low, Model: "low"}, {Registry: high, Model: "high"}}
	config := &registry.SmartRoutingConfig{SR1: &registry.SR1Config{CacheTTLSeconds: 300}, Tiers: []registry.SmartRoutingTier{{RegistryID: low.ID, Model: "low", MinScore: 0}, {RegistryID: high.ID, Model: "high", MinScore: .45}}}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"revision":"test-revision","raw_score":0.9}`))
	}))
	t.Cleanup(srv.Close)
	scorer := complexity.NewClient(srv.URL, firewall.NewTokenProvider("synthetic-signing-secret"), time.Second, "test-revision")
	factory := loadbalancer.NewBaseFactory(nil, nil, scorer, strategies.NewRedisSR1Store(client), newTestLogger())
	lb, err := loadbalancer.NewLoadBalancer(factory, loadbalancer.Pool{Routes: routes, Algorithm: loadbalancer.AlgorithmSmartRouting, SmartRoutingConfig: config}, newTestLogger(), cache)
	require.NoError(t, err)
	t.Cleanup(lb.Close)
	req := &infracontext.RequestContext{GatewayID: "gateway", ConsumerID: "consumer", SessionID: "session", Body: []byte(`{"prompt":"synthetic"}`)}
	got, err := lb.NextRoute(ctx, req, nil)
	require.NoError(t, err)
	require.Equal(t, high.ID, got.Registry.ID)
	require.EqualValues(t, 1, calls.Load())
	lb.ReportFailure(high, errors.New("provider unavailable"))
	_, err = lb.NextRoute(ctx, req, nil)
	require.ErrorIs(t, err, routingdomain.ErrSR1PolicyExhausted, "a warm strongest commitment cannot downgrade")
	status, err := json.Marshal(loadbalancer.HealthStatus{Healthy: false, LastCheck: time.Now().Add(-61 * time.Second), Failures: 1})
	require.NoError(t, err)
	require.NoError(t, client.Set(ctx, fmt.Sprintf("lb:health:%s", high.ID), status, time.Hour).Err())
	_, err = lb.NextRoute(ctx, req, map[routingdomain.RouteKey]struct{}{routes[1].Key(): {}})
	require.ErrorIs(t, err, routingdomain.ErrSR1PolicyExhausted, "cooldown does not erase the request exclusion")
	got, err = lb.NextRoute(ctx, req, nil)
	require.NoError(t, err)
	require.Equal(t, high.ID, got.Registry.ID, "recover the bound route before the one-hour health cache expires")
	require.EqualValues(t, 1, calls.Load(), "warm recovery does not rescore or spend an escape")
	lb.UpdateBackendHealth(high, true, nil)
	got, err = lb.NextRoute(ctx, req, nil)
	require.NoError(t, err)
	require.Equal(t, high.ID, got.Registry.ID)
}
