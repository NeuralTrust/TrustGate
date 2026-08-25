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
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nilRedis makes the balancer skip every health round-trip, which the baseline
// resolver never needs: it reads the pool's config, not backend health.
type nilRedis struct{}

func (nilRedis) RedisClient() *redis.Client { return nil }

func baselineRegistry(provider, model string, pricing *registrydomain.Pricing) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: model,
		Type: registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: provider,
			Auth:     registrydomain.NewAPIKeyAuth("sk-1"),
			Pricing:  pricing,
		},
	}
}

func baselineBalancer(t *testing.T, alg string, routes []routingdomain.Route, cfg *registrydomain.SmartRoutingConfig) *loadbalancer.LoadBalancer {
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
	cheap := baselineRegistry("openai", "gpt-4o-mini", nil)
	premium := baselineRegistry("anthropic", "claude-opus", &registrydomain.Pricing{Discount: 0.25})
	routes := []routingdomain.Route{
		{Registry: cheap, Model: "gpt-4o-mini"},
		{Registry: premium, Model: "claude-opus"},
	}
	tiers := func(topModel string) *registrydomain.SmartRoutingConfig {
		return &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: cheap.ID, Model: "gpt-4o-mini"},
			{MinScore: 0.8, RegistryID: premium.ID, Model: topModel},
		}}
	}

	t.Run("resolves the top tier to its route", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, routes, tiers("claude-opus"))

		base := smartRoutingBaseline(lb)

		require.NotNil(t, base)
		assert.Equal(t, premium.ID.String(), base.RegistryID)
		assert.Equal(t, "anthropic", base.Provider)
		assert.Equal(t, "claude-opus", base.Model)
		assert.InDelta(t, 0.8, base.MinScore, 1e-12)
		require.NotNil(t, base.Pricing)
		assert.InDelta(t, 0.25, base.Pricing.Discount, 1e-12)
	})

	t.Run("falls back to the route model when the tier pins none", func(t *testing.T) {
		cfg := &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{
			{MinScore: 0, RegistryID: cheap.ID},
			{MinScore: 0.8, RegistryID: premium.ID},
		}}
		lb := baselineBalancer(t, algorithm.SmartRouting, routes, cfg)

		base := smartRoutingBaseline(lb)

		require.NotNil(t, base)
		assert.Equal(t, "claude-opus", base.Model)
	})

	// Pricing a target the balancer could never have picked would be fiction, so
	// a tier that matches no route in the pool yields no baseline at all.
	t.Run("no baseline when the top tier matches no route", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.SmartRouting, routes, tiers("claude-sonnet"))

		assert.Nil(t, smartRoutingBaseline(lb))
	})

	t.Run("no baseline for other algorithms", func(t *testing.T) {
		lb := baselineBalancer(t, algorithm.RoundRobin, routes, nil)

		assert.Nil(t, smartRoutingBaseline(lb))
	})

	t.Run("no baseline without a balancer", func(t *testing.T) {
		assert.Nil(t, smartRoutingBaseline(nil))
	})
}
