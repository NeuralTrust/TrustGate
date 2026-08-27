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

package catalog

import (
	"context"
	"io"
	"log/slog"
	"math"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type priceRepo struct {
	*fakeRepo
	byKey map[string]*domain.Model
	err   error
	calls int
}

func (p *priceRepo) FindModel(_ context.Context, providerCode string, slug string) (*domain.Model, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	if p.byKey != nil {
		if m, ok := p.byKey[providerCode+":"+slug]; ok {
			return m, nil
		}
		return nil, commonerrors.ErrNotFound
	}
	return nil, commonerrors.ErrNotFound
}

func newPricingResolver(repo domain.Repository) PricingResolver {
	mgr := cache.NewTTLMapManager(cache.CatalogModelCacheTTL)
	mgr.CreateTTLMap(cache.CatalogModelTTLName, cache.CatalogModelCacheTTL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewPricingResolver(repo, mgr, logger)
}

func TestPricingResolver_ComputesPriceAndCachesLookup(t *testing.T) {
	repo := &priceRepo{
		fakeRepo: newFakeRepo(),
		byKey: map[string]*domain.Model{
			"openai:gpt-4o": {
				DisplayName: "GPT-4o",
				InputPrice:  "0.0000025",
				OutputPrice: "0.00001",
			},
		},
	}
	resolver := newPricingResolver(repo)

	first := resolver.Resolve(context.Background(), "openai", "gpt-4o")
	require.True(t, first.Found)
	assert.Equal(t, "GPT-4o", first.ModelLabel)
	assert.InDelta(t, 0.0000025, first.InputPrice, 1e-12)
	assert.InDelta(t, 0.00001, first.OutputPrice, 1e-12)

	second := resolver.Resolve(context.Background(), "openai", "gpt-4o")
	assert.Equal(t, first, second)
	assert.Equal(t, 1, repo.calls, "second resolve must be served from cache")
}

func TestPricingResolver_CachesNegativeLookup(t *testing.T) {
	repo := &priceRepo{fakeRepo: newFakeRepo(), err: commonerrors.ErrNotFound}
	resolver := newPricingResolver(repo)

	first := resolver.Resolve(context.Background(), "openai", "unknown")
	assert.False(t, first.Found)

	second := resolver.Resolve(context.Background(), "openai", "unknown")
	assert.False(t, second.Found)
	assert.Equal(t, 1, repo.calls, "negative lookups must be cached to keep the hot path off the DB")
}

func TestPricingResolver_EmptyKeySkipsLookup(t *testing.T) {
	repo := &priceRepo{fakeRepo: newFakeRepo()}
	resolver := newPricingResolver(repo)

	assert.False(t, resolver.Resolve(context.Background(), "", "gpt-4o").Found)
	assert.False(t, resolver.Resolve(context.Background(), "openai", "").Found)
	assert.Equal(t, 0, repo.calls)
}

func TestPricingResolver_OpenAICompatibleFallsBackToOpenAIPrices(t *testing.T) {
	repo := &priceRepo{
		fakeRepo: newFakeRepo(),
		byKey: map[string]*domain.Model{
			"openai:gpt-4o": {
				DisplayName: "GPT-4o",
				InputPrice:  "0.0000025",
				OutputPrice: "0.00001",
			},
		},
	}
	resolver := newPricingResolver(repo)

	got := resolver.Resolve(context.Background(), providers.ProviderOpenAICompatible, "gpt-4o")
	require.True(t, got.Found)
	assert.Equal(t, "GPT-4o", got.ModelLabel)
	assert.InDelta(t, 0.0000025, got.InputPrice, 1e-12)
	assert.InDelta(t, 0.00001, got.OutputPrice, 1e-12)
	assert.Equal(t, 2, repo.calls, "compatible miss then openai hit")

	cached := resolver.Resolve(context.Background(), providers.ProviderOpenAICompatible, "gpt-4o")
	assert.Equal(t, got, cached)
	assert.Equal(t, 2, repo.calls, "compatible hit must stay cached under openai_compatible key")
}

func TestPricingResolver_EmptyPricesAreNotFound(t *testing.T) {
	repo := &priceRepo{
		fakeRepo: newFakeRepo(),
		byKey: map[string]*domain.Model{
			"openai:free-model": {
				DisplayName: "Free",
				InputPrice:  "",
				OutputPrice: "",
			},
		},
	}
	resolver := newPricingResolver(repo)

	got := resolver.Resolve(context.Background(), "openai", "free-model")
	assert.False(t, got.Found)
}

func TestPricingResolver_InvalidateCacheDropsNegativeAndPositiveEntries(t *testing.T) {
	repo := &priceRepo{
		fakeRepo: newFakeRepo(),
		byKey: map[string]*domain.Model{
			"openai:gpt-4o": {
				DisplayName: "GPT-4o",
				InputPrice:  "0.0000025",
				OutputPrice: "0.00001",
			},
		},
	}
	resolver := newPricingResolver(repo)

	require.True(t, resolver.Resolve(context.Background(), "openai", "gpt-4o").Found)
	assert.Equal(t, 1, repo.calls)

	resolver.InvalidateCache()

	require.True(t, resolver.Resolve(context.Background(), "openai", "gpt-4o").Found)
	assert.Equal(t, 2, repo.calls, "after invalidate the next resolve must hit the repository again")
}

func TestParsePrice(t *testing.T) {
	assert.InDelta(t, 0.0000025, parsePrice("0.0000025"), 1e-12)
	assert.Equal(t, 0.0, parsePrice(""))
	assert.Equal(t, 0.0, parsePrice("not-a-number"))
}

func TestParsePrice_RejectsNonFiniteValues(t *testing.T) {
	for _, raw := range []string{"NaN", "nan", "Inf", "inf", "+Inf", "-Inf", "Infinity", "-Infinity"} {
		t.Run(raw, func(t *testing.T) {
			got := parsePrice(raw)
			require.False(t, math.IsNaN(got), "a NaN rate prices every request against it as NaN")
			require.False(t, math.IsInf(got, 0), "an infinite rate does the same")
			assert.Equal(t, 0.0, got, "discarded exactly like an unparseable value")
		})
	}
}

// strconv.ParseFloat reports an error for an out-of-range literal but still
// returns +Inf, so the error check alone is not what keeps this one out.
func TestParsePrice_OverflowIsAlsoDiscarded(t *testing.T) {
	assert.Equal(t, 0.0, parsePrice("1e999"))
}

func TestCoalescePrice_InheritsTheNonFiniteGuard(t *testing.T) {
	assert.Equal(t, 0.0, coalescePrice("NaN", 0.5),
		"a non-finite override must not reach the cache rates either")
	assert.InDelta(t, 0.5, coalescePrice("", 0.5), 1e-12)
	assert.InDelta(t, 0.25, coalescePrice("0.25", 0.5), 1e-12)
}
