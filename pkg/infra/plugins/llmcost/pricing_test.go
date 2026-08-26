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

package llmcost

import (
	"context"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPer1k(t *testing.T) {
	assert.InDelta(t, 0.0025, Per1k(0.0000025), 1e-12)
	assert.InDelta(t, 0, Per1k(0), 1e-12)
}

func TestMicroUSD(t *testing.T) {
	tests := []struct {
		name string
		cost float64
		want int64
	}{
		{name: "spec example", cost: 1000*0.000010 + 500*0.000030, want: 25000},
		{name: "rounds half away from zero", cost: 0.0000005, want: 1},
		{name: "rounds down below half", cost: 0.0000004, want: 0},
		{name: "zero", cost: 0, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MicroUSD(tt.cost))
		})
	}
}

func TestPriceFor_CustomOverlay(t *testing.T) {
	tests := []struct {
		name      string
		pricing   map[string]CustomPrice
		model     string
		wantIn    float64
		wantOut   float64
		wantFound bool
	}{
		{
			name:      "exact custom match",
			pricing:   map[string]CustomPrice{"gpt-4o-mini": {Input: 0.1, Output: 0.2}},
			model:     "gpt-4o-mini",
			wantIn:    0.1,
			wantOut:   0.2,
			wantFound: true,
		},
		{
			name:      "glob custom match",
			pricing:   map[string]CustomPrice{"gpt-4o-*": {Input: 0.3, Output: 0.4}},
			model:     "gpt-4o-mini",
			wantIn:    0.3,
			wantOut:   0.4,
			wantFound: true,
		},
		{
			name: "exact beats glob",
			pricing: map[string]CustomPrice{
				"gpt-4o-*":    {Input: 9, Output: 9},
				"gpt-4o-mini": {Input: 0.1, Output: 0.2},
			},
			model:     "gpt-4o-mini",
			wantIn:    0.1,
			wantOut:   0.2,
			wantFound: true,
		},
		{
			name:      "date-suffixed model matches base custom key",
			pricing:   map[string]CustomPrice{"gpt-4o-mini": {Input: 0.1, Output: 0.2}},
			model:     "gpt-4o-mini-2024-07-18",
			wantIn:    0.1,
			wantOut:   0.2,
			wantFound: true,
		},
		{
			name:      "no match",
			pricing:   map[string]CustomPrice{"gpt-4o-mini": {Input: 0.1, Output: 0.2}},
			model:     "claude-opus-4",
			wantFound: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rates, found := PriceFor(context.Background(), nil, tt.pricing, "openai", tt.model)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.InDelta(t, tt.wantIn, rates.Input, 1e-12)
				assert.InDelta(t, tt.wantOut, rates.Output, 1e-12)
			}
		})
	}
}

func TestPriceFor_BuiltinFallback(t *testing.T) {
	resolver := catalogmocks.NewPricingResolver(t)
	resolver.EXPECT().
		Resolve(mock.Anything, "openai", "gpt-4o-mini-2024-07-18").
		Return(appcatalog.Pricing{}).Once()
	resolver.EXPECT().
		Resolve(mock.Anything, "openai", "gpt-4o-mini").
		Return(appcatalog.Pricing{Found: true, InputPrice: 0.3, OutputPrice: 0.4}).Once()

	rates, found := PriceFor(context.Background(), resolver, nil, "openai", "gpt-4o-mini-2024-07-18")
	require.True(t, found)
	assert.InDelta(t, 0.3, rates.Input, 1e-12)
	assert.InDelta(t, 0.4, rates.Output, 1e-12)
}

func TestPriceFor_CustomWinsOverBuiltin(t *testing.T) {
	resolver := catalogmocks.NewPricingResolver(t)

	custom := map[string]CustomPrice{"gpt-4o-mini": {Input: 0.1, Output: 0.2}}
	rates, found := PriceFor(context.Background(), resolver, custom, "openai", "gpt-4o-mini")
	require.True(t, found)
	assert.InDelta(t, 0.1, rates.Input, 1e-12)
	assert.InDelta(t, 0.2, rates.Output, 1e-12)
}

func TestPriceFor_NoResolverNoCustom(t *testing.T) {
	_, found := PriceFor(context.Background(), nil, nil, "openai", "gpt-4o-mini")
	assert.False(t, found)
}

func TestResolve_RegistryPrecedence(t *testing.T) {
	t.Parallel()
	resolver := catalogmocks.NewPricingResolver(t)
	resolver.EXPECT().
		Resolve(mock.Anything, "openai", mock.Anything).
		Return(appcatalog.Pricing{Found: true, InputPrice: 0.000002, OutputPrice: 0.000008}).
		Maybe()

	tests := []struct {
		name      string
		custom    map[string]CustomPrice
		registry  *RegistryRates
		model     string
		wantIn    float64
		wantOut   float64
		wantFound bool
	}{
		{
			name:      "policy custom wins over registry override",
			custom:    map[string]CustomPrice{"gpt-4o": {Input: 0.1, Output: 0.2}},
			registry:  &RegistryRates{Discount: 0.2, Overrides: map[string]CustomPrice{"gpt-4o": {Input: 0.0000015, Output: 0.000006}}},
			model:     "gpt-4o",
			wantIn:    0.1,
			wantOut:   0.2,
			wantFound: true,
		},
		{
			name:      "absolute override wins over discount",
			registry:  &RegistryRates{Discount: 0.2, Overrides: map[string]CustomPrice{"gpt-4o": {Input: 0.0000015, Output: 0.000006}}},
			model:     "gpt-4o",
			wantIn:    0.0000015,
			wantOut:   0.000006,
			wantFound: true,
		},
		{
			name:      "discount applies to catalog when no override",
			registry:  &RegistryRates{Discount: 0.2},
			model:     "gpt-4o-mini",
			wantIn:    0.000002 * 0.8,
			wantOut:   0.000008 * 0.8,
			wantFound: true,
		},
		{
			name:      "exact override beats glob",
			registry:  &RegistryRates{Overrides: map[string]CustomPrice{"gpt-4o-*": {Input: 9, Output: 9}, "gpt-4o-mini": {Input: 0.0000001, Output: 0.0000004}}},
			model:     "gpt-4o-mini",
			wantIn:    0.0000001,
			wantOut:   0.0000004,
			wantFound: true,
		},
		{
			name:      "unmatched model falls through to catalog",
			registry:  &RegistryRates{Overrides: map[string]CustomPrice{"claude-*": {Input: 1, Output: 1}}},
			model:     "gpt-4o-mini",
			wantIn:    0.000002,
			wantOut:   0.000008,
			wantFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rates, found := Resolve(context.Background(), resolver, tt.custom, tt.registry, "openai", tt.model)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.InDelta(t, tt.wantIn, rates.Input, 1e-12)
				assert.InDelta(t, tt.wantOut, rates.Output, 1e-12)
			}
		})
	}
}

func TestRatesFromDomain(t *testing.T) {
	t.Parallel()
	assert.Nil(t, RatesFromDomain(nil))
	assert.Nil(t, RatesFromDomain(&domain.Pricing{}))

	got := RatesFromDomain(&domain.Pricing{
		Discount: 0.2,
		Overrides: map[string]domain.PriceOverride{
			"gpt-4o": {Input: 0.0000015, Output: 0.000006},
		},
	})
	require.NotNil(t, got)
	assert.InDelta(t, 0.2, got.Discount, 1e-12)
	assert.InDelta(t, 0.0000015, got.Overrides["gpt-4o"].Input, 1e-12)
}

// One expression has to be correct for every provider: the adapters guarantee
// InputTokens is the whole prompt and each cache count is a strict subset of it.
func TestRates_CostUSD_PricesEachPromptBucketAtItsOwnRate(t *testing.T) {
	t.Parallel()
	// Anthropic sonnet list rates, per token.
	r := Rates{Input: 3.00 / 1e6, Output: 15.00 / 1e6, CacheRead: 0.30 / 1e6, CacheWrite: 3.75 / 1e6}

	tests := []struct {
		name       string
		usage      *adapter.CanonicalUsage
		wantPrompt float64
	}{
		{
			name:       "cache read: the cached share bills at a tenth",
			usage:      &adapter.CanonicalUsage{InputTokens: 8416, OutputTokens: 4, CachedInputTokens: 8403},
			wantPrompt: 13*(3.00/1e6) + 8403*(0.30/1e6),
		},
		{
			name:       "cache write: the written share bills at a premium",
			usage:      &adapter.CanonicalUsage{InputTokens: 8416, OutputTokens: 4, CacheWriteInputTokens: 8403},
			wantPrompt: 13*(3.00/1e6) + 8403*(3.75/1e6),
		},
		{
			name: "both buckets at once, disjoint from each other",
			usage: &adapter.CanonicalUsage{
				InputTokens: 1000, OutputTokens: 10,
				CachedInputTokens: 600, CacheWriteInputTokens: 300,
			},
			wantPrompt: 100*(3.00/1e6) + 600*(0.30/1e6) + 300*(3.75/1e6),
		},
		{
			name:       "no cache at all is the plain rate",
			usage:      &adapter.CanonicalUsage{InputTokens: 500, OutputTokens: 10},
			wantPrompt: 500 * (3.00 / 1e6),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			prompt, completion := r.CostUSD(tt.usage)
			assert.InDelta(t, tt.wantPrompt, prompt, 1e-15)
			assert.InDelta(t, float64(tt.usage.OutputTokens)*r.Output, completion, 1e-15)
		})
	}
}

// An unpublished cache rate must bill at the plain input rate, which is what the
// gateway charged before cache rates existed. Zero would silently make most of a
// cached prompt free.
func TestResolve_UnsetCacheRateFallsBackToInput(t *testing.T) {
	t.Parallel()
	resolver := catalogmocks.NewPricingResolver(t)
	resolver.EXPECT().
		Resolve(mock.Anything, "openai", mock.Anything).
		Return(appcatalog.Pricing{Found: true, InputPrice: 0.000002, OutputPrice: 0.000008}).
		Maybe()

	rates, found := Resolve(context.Background(), resolver, nil, nil, "openai", "gpt-4o-mini")
	require.True(t, found)
	assert.InDelta(t, 0.000002, rates.CacheRead, 1e-15, "unset cache read bills as plain input")
	assert.InDelta(t, 0.000002, rates.CacheWrite, 1e-15, "unset cache write bills as plain input")

	u := &adapter.CanonicalUsage{InputTokens: 1000, OutputTokens: 0, CachedInputTokens: 900}
	prompt, _ := rates.CostUSD(u)
	assert.InDelta(t, 1000*0.000002, prompt, 1e-15,
		"a model with no published cache rate costs exactly what it did before")
}

// An override that names only input and output must not make cached tokens free.
func TestResolve_OverrideWithoutCacheRatesKeepsItsOwnInputRate(t *testing.T) {
	t.Parallel()
	custom := map[string]CustomPrice{"gpt-4o-mini": {Input: 0.000005, Output: 0.00002}}

	rates, found := Resolve(context.Background(), nil, custom, nil, "openai", "gpt-4o-mini")
	require.True(t, found)
	assert.InDelta(t, 0.000005, rates.CacheRead, 1e-15)
	assert.InDelta(t, 0.000005, rates.CacheWrite, 1e-15)

	cheap := 0.0000005
	custom2 := map[string]CustomPrice{"gpt-4o-mini": {Input: 0.000005, Output: 0.00002, CacheRead: &cheap}}
	rates2, found2 := Resolve(context.Background(), nil, custom2, nil, "openai", "gpt-4o-mini")
	require.True(t, found2)
	assert.InDelta(t, cheap, rates2.CacheRead, 1e-15, "an explicit cache rate is honoured")
	assert.InDelta(t, 0.000005, rates2.CacheWrite, 1e-15, "the unset one still falls back")
}
