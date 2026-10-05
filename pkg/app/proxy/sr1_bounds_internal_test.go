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

package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/strategies"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type sr1BoundsRedis struct{ client *redis.Client }

func (s sr1BoundsRedis) RedisClient() *redis.Client { return s.client }

func TestSR1ForwarderBounds(t *testing.T) {
	low := baselineRegistry("openai", nil)
	high := baselineRegistry("anthropic", nil)
	outside := baselineRegistry("openai", nil)
	cfg := &registrydomain.SmartRoutingConfig{SR1: &registrydomain.SR1Config{CacheTTLSeconds: 60}, Tiers: []registrydomain.SmartRoutingTier{{RegistryID: low.ID, Model: "low", MinScore: 0}, {RegistryID: high.ID, Model: "high", MinScore: .45}}}
	rc := &appconsumer.RoutableConsumer{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), LBConfig: &domainconsumer.LBConfig{Enabled: true, Algorithm: loadbalancer.AlgorithmSmartRouting, SmartRouting: cfg, Members: []domainconsumer.LBPoolMember{{RegistryID: low.ID, Model: "low"}, {RegistryID: high.ID, Model: "high"}}}, Fallback: &domainconsumer.Fallback{Chain: registrydomain.Registries{outside.ID}}}, Registries: []*registrydomain.Registry{low, high}, FallbackBackends: []*registrydomain.Registry{outside}}
	ttl := cache.NewTTLMap(time.Minute)
	t.Cleanup(ttl.Clear)
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	f := &forwarder{balancers: newLoadBalancerCache(loadbalancer.NewBaseFactoryWithSR1(nil, nil, nil, strategies.NewRedisSR1Store(client), nil), sr1BoundsRedis{client}, ttl, nil)}
	lb, err := f.balancers.For(rc)
	require.NoError(t, err)
	t.Cleanup(lb.Close)
	req := &infracontext.RequestContext{SessionID: "warm", Body: []byte(`{"prompt":"hard"}`)}
	top, err := lb.NextRoute(context.Background(), req, nil)
	require.NoError(t, err)
	require.Equal(t, "high", top.Model)
	excluded := map[routingdomain.RouteKey]struct{}{top.Key(): {}}
	next, viaFallback := f.nextCandidate(context.Background(), lb, rc, req, nil, excluded, true)
	require.Nil(t, next)
	require.False(t, viaFallback)
	candidates := routingdomain.NewCandidateSet()
	candidates.Add(routingdomain.Candidate{Registry: outside})
	_, err = f.routeBackend(context.Background(), rc, req, routingdomain.Intent{}, candidates)
	require.True(t, errors.Is(err, routingdomain.ErrSR1PolicyExhausted), "error=%v", err)
	require.True(t, errors.Is(err, ErrNoBackendAvailable), "error=%v", err)
}
