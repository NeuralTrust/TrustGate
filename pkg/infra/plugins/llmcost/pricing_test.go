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
			in, out, found := PriceFor(context.Background(), nil, tt.pricing, "openai", tt.model)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.InDelta(t, tt.wantIn, in, 1e-12)
				assert.InDelta(t, tt.wantOut, out, 1e-12)
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

	in, out, found := PriceFor(context.Background(), resolver, nil, "openai", "gpt-4o-mini-2024-07-18")
	require.True(t, found)
	assert.InDelta(t, 0.3, in, 1e-12)
	assert.InDelta(t, 0.4, out, 1e-12)
}

func TestPriceFor_CustomWinsOverBuiltin(t *testing.T) {
	resolver := catalogmocks.NewPricingResolver(t)

	custom := map[string]CustomPrice{"gpt-4o-mini": {Input: 0.1, Output: 0.2}}
	in, out, found := PriceFor(context.Background(), resolver, custom, "openai", "gpt-4o-mini")
	require.True(t, found)
	assert.InDelta(t, 0.1, in, 1e-12)
	assert.InDelta(t, 0.2, out, 1e-12)
}

func TestPriceFor_NoResolverNoCustom(t *testing.T) {
	_, _, found := PriceFor(context.Background(), nil, nil, "openai", "gpt-4o-mini")
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
			in, out, found := Resolve(context.Background(), resolver, tt.custom, tt.registry, "openai", tt.model)
			assert.Equal(t, tt.wantFound, found)
			if tt.wantFound {
				assert.InDelta(t, tt.wantIn, in, 1e-12)
				assert.InDelta(t, tt.wantOut, out, 1e-12)
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
