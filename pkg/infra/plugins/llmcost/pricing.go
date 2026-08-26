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
	"log/slog"
	"math"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type CustomPrice struct {
	Input  float64 `mapstructure:"input" json:"input"`
	Output float64 `mapstructure:"output" json:"output"`
	// CacheRead and CacheWrite are pointers so an override that names only input
	// and output keeps charging cached tokens at its own input rate, instead of
	// silently making them free.
	CacheRead  *float64 `mapstructure:"cache_read" json:"cache_read,omitempty"`
	CacheWrite *float64 `mapstructure:"cache_write" json:"cache_write,omitempty"`
	// CacheWrite1h prices the share written with a one-hour TTL, which Anthropic
	// bills above its five-minute default. No catalog publishes a rate for it, so
	// it defaults to CacheWrite and only an explicit override makes it exact.
	CacheWrite1h *float64 `mapstructure:"cache_write_1h" json:"cache_write_1h,omitempty"`
}

// Rates are the per-token rates a prompt and completion are billed at. Cached
// and cache-written prompt tokens are sub-populations of the prompt that bill at
// their own rate; the rest bills at Input.
type Rates struct {
	Input        float64
	Output       float64
	CacheRead    float64
	CacheWrite   float64
	CacheWrite1h float64
}

// orInput reads an unset cache rate as the plain input rate. The catalog does
// the same coalescing when it loads a model, but a Pricing can reach here from
// any resolver, and a zero rate would silently make cached tokens free — which
// is the failure mode worth being paranoid about in a billing path.
func orInput(rate, input float64) float64 {
	if rate <= 0 {
		return input
	}
	return rate
}

func ratesFor(input, output float64, cacheRead, cacheWrite, cacheWrite1h *float64) Rates {
	r := Rates{Input: input, Output: output, CacheRead: input, CacheWrite: input}
	if cacheRead != nil {
		r.CacheRead = *cacheRead
	}
	if cacheWrite != nil {
		r.CacheWrite = *cacheWrite
	}
	r.CacheWrite1h = r.CacheWrite
	if cacheWrite1h != nil {
		r.CacheWrite1h = *cacheWrite1h
	}
	return r
}

// CostUSD prices a canonical usage view. It is correct for every provider
// because the adapters guarantee InputTokens is the whole prompt and every cache
// count is a strict subset of it.
func (r Rates) CostUSD(u *adapter.CanonicalUsage) (promptUSD, completionUSD float64) {
	if u == nil {
		return 0, 0
	}
	cached, written := u.CachedInputTokens, u.CacheWriteInputTokens
	plain := u.PlainInputTokens()
	if plain == u.InputTokens && cached+written > 0 {
		slog.Warn("llmcost: usage sub-counts exceed the prompt they claim to be part of; "+
			"billing the whole prompt at the input rate",
			slog.Int("input_tokens", u.InputTokens),
			slog.Int("cached_input_tokens", cached),
			slog.Int("cache_write_input_tokens", written))
		cached, written = 0, 0
	}
	written1h := u.CacheWrite1hInputTokens
	if written1h > written {
		written1h = written
	}
	promptUSD = float64(plain)*r.Input +
		float64(cached)*r.CacheRead +
		float64(written-written1h)*r.CacheWrite +
		float64(written1h)*r.CacheWrite1h
	return promptUSD, float64(u.OutputTokens) * r.Output
}

type RegistryRates struct {
	Discount  float64
	Overrides map[string]CustomPrice
}

func RatesFromDomain(p *domain.Pricing) *RegistryRates {
	if p.IsZero() {
		return nil
	}
	rates := &RegistryRates{Discount: p.Discount}
	if len(p.Overrides) == 0 {
		return rates
	}
	rates.Overrides = make(map[string]CustomPrice, len(p.Overrides))
	for slug, rate := range p.Overrides {
		rates.Overrides[slug] = CustomPrice{
			Input: rate.Input, Output: rate.Output,
			CacheRead: rate.CacheRead, CacheWrite: rate.CacheWrite,
			CacheWrite1h: rate.CacheWrite1h,
		}
	}
	return rates
}

func PriceFor(ctx context.Context, resolver appcatalog.PricingResolver, custom map[string]CustomPrice, provider string, models ...string) (Rates, bool) {
	return Resolve(ctx, resolver, custom, nil, provider, models...)
}

func Resolve(ctx context.Context, resolver appcatalog.PricingResolver, custom map[string]CustomPrice, registry *RegistryRates, provider string, models ...string) (Rates, bool) {
	candidates := appcatalog.SlugCandidates(models...)
	for _, slug := range candidates {
		if cp, ok := BestMatch(custom, slug); ok {
			return ratesFor(cp.Input, cp.Output, cp.CacheRead, cp.CacheWrite, cp.CacheWrite1h), true
		}
	}
	if registry != nil {
		for _, slug := range candidates {
			if cp, ok := BestMatch(registry.Overrides, slug); ok {
				return ratesFor(cp.Input, cp.Output, cp.CacheRead, cp.CacheWrite, cp.CacheWrite1h), true
			}
		}
	}
	if resolver == nil || provider == "" {
		return Rates{}, false
	}
	for _, slug := range candidates {
		price := resolver.Resolve(ctx, provider, slug)
		if !price.Found {
			continue
		}
		r := Rates{
			Input:      price.InputPrice,
			Output:     price.OutputPrice,
			CacheRead:  orInput(price.CacheReadPrice, price.InputPrice),
			CacheWrite: orInput(price.CacheWritePrice, price.InputPrice),
		}
		r.CacheWrite1h = r.CacheWrite
		if registry != nil && registry.Discount > 0 {
			factor := 1 - registry.Discount
			r.Input *= factor
			r.Output *= factor
			r.CacheRead *= factor
			r.CacheWrite *= factor
			r.CacheWrite1h *= factor
		}
		return r, true
	}
	return Rates{}, false
}

// Per1k converts a per-token rate to a per-1000-token rate.
func Per1k(perToken float64) float64 {
	return perToken * 1000
}

// MicroUSD converts a USD amount to micro-USD, rounding half away from zero.
func MicroUSD(costUSD float64) int64 {
	return int64(math.Round(costUSD * 1e6))
}
