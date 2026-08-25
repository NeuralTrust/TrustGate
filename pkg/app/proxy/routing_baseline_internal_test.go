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
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type nilRedis struct{}

func (nilRedis) RedisClient() *redis.Client { return nil }

func baselineRegistry(provider string, pricing *registrydomain.Pricing) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: provider,
		Type: registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: provider,
			Auth:     registrydomain.NewAPIKeyAuth("sk-1"),
			Pricing:  pricing,
		},
	}
}

func baselineBalancer(
	t *testing.T,
	alg string,
	routes []routingdomain.Route,
	cfg *registrydomain.SmartRoutingConfig,
) *loadbalancer.LoadBalancer {
	t.Helper()
	lb, err := loadbalancer.NewLoadBalancer(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil),
		loadbalancer.Pool{ID: "pool", Routes: routes, Algorithm: alg, SmartRoutingConfig: cfg},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nilRedis{},
	)
	require.NoError(t, err)
	t.Cleanup(lb.Close)
	return lb
}

func TestSmartRoutingBaseline(t *testing.T) {
	cheap := baselineRegistry("openai", nil)
	premium := baselineRegistry("anthropic", &registrydomain.Pricing{Discount: 0.25})
	pinnedRoutes := []routingdomain.Route{
		{Registry: cheap, Model: "gpt-4o-mini"},
		{Registry: premium, Model: "claude-opus"},
	}
	tiers := func(topModel string) *registrydomain.SmartRoutingConfig {
		return &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: cheap.ID, Model: "gpt-4o-mini"},
			{MinScore: 0.8, RegistryID: premium.ID, Model: topModel},
		}}
	}
	unpinnedTiers := &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{
		{MinScore: 0, RegistryID: cheap.ID},
		{MinScore: 0.8, RegistryID: premium.ID},
	}}

	t.Run("resolves the top tier to its route", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, pinnedRoutes, tiers("claude-opus"))

		base := smartRoutingBaseline(lb, nil)

		require.NotNil(t, base)
		assert.Equal(t, "anthropic", base.Provider)
		assert.Equal(t, "claude-opus", base.Model)
		require.NotNil(t, base.Pricing)
		assert.InDelta(t, 0.25, base.Pricing.Discount, 1e-12)
	})

	t.Run("an unpinned tier takes the route model", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, pinnedRoutes, unpinnedTiers)

		base := smartRoutingBaseline(lb, nil)

		require.NotNil(t, base)
		assert.Equal(t, "claude-opus", base.Model)
	})

	t.Run("an unpinned tier on an unpinned route takes the consumer default", func(t *testing.T) {
		routes := []routingdomain.Route{
			{Registry: cheap, Default: "gpt-4o-mini"},
			{Registry: premium, Default: "claude-opus"},
		}
		lb := baselineBalancer(t, algorithm.SmartRouting, routes, unpinnedTiers)

		base := smartRoutingBaseline(lb, nil)

		require.NotNil(t, base)
		assert.Equal(t, "claude-opus", base.Model)
	})

	t.Run("no baseline when the top tier resolves to no model at all", func(t *testing.T) {
		routes := []routingdomain.Route{{Registry: cheap}, {Registry: premium}}
		lb := baselineBalancer(t, algorithm.SmartRouting, routes, unpinnedTiers)

		assert.Nil(t, smartRoutingBaseline(lb, nil))
	})

	t.Run("no baseline when the top tier matches no route", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, pinnedRoutes, tiers("claude-sonnet"))

		assert.Nil(t, smartRoutingBaseline(lb, nil))
	})

	t.Run("no baseline when the top tier is excluded for this request", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, pinnedRoutes, tiers("claude-opus"))
		excluded := map[routingdomain.RouteKey]struct{}{pinnedRoutes[1].Key(): {}}

		assert.Nil(t, smartRoutingBaseline(lb, excluded),
			"the strategy could not have picked it either, so pricing against it would be fiction")
	})

	t.Run("no baseline for other algorithms", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.RoundRobin, pinnedRoutes, tiers("claude-opus"))

		assert.Nil(t, smartRoutingBaseline(lb, nil))
	})

	t.Run("no baseline without a balancer", func(t *testing.T) {
		assert.Nil(t, smartRoutingBaseline(nil, nil))
	})
}

func TestTakeTierRouted(t *testing.T) {
	t.Run("reports and drains a tier decision", func(t *testing.T) {
		req := &infracontext.RequestContext{
			RoutingDecision: &infracontext.RoutingDecision{TierApplied: true},
		}

		assert.True(t, takeTierRouted(req))
		assert.Nil(t, req.RoutingDecision,
			"a hop that never consults the strategy must not inherit this decision")
		assert.False(t, takeTierRouted(req))
	})

	t.Run("reports false for a fail-open decision", func(t *testing.T) {
		req := &infracontext.RequestContext{
			RoutingDecision: &infracontext.RoutingDecision{TierApplied: false},
		}

		assert.False(t, takeTierRouted(req))
		assert.Nil(t, req.RoutingDecision)
	})

	t.Run("reports false when no strategy decided", func(t *testing.T) {
		assert.False(t, takeTierRouted(&infracontext.RequestContext{}))
		assert.False(t, takeTierRouted(nil))
	})
}
