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
	"math"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type CustomPrice struct {
	Input  float64 `mapstructure:"input" json:"input"`
	Output float64 `mapstructure:"output" json:"output"`
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
		rates.Overrides[slug] = CustomPrice{Input: rate.Input, Output: rate.Output}
	}
	return rates
}

func PriceFor(ctx context.Context, resolver appcatalog.PricingResolver, custom map[string]CustomPrice, provider string, models ...string) (float64, float64, bool) {
	return Resolve(ctx, resolver, custom, nil, provider, models...)
}

func Resolve(ctx context.Context, resolver appcatalog.PricingResolver, custom map[string]CustomPrice, registry *RegistryRates, provider string, models ...string) (float64, float64, bool) {
	candidates := appcatalog.SlugCandidates(models...)
	for _, slug := range candidates {
		if cp, ok := BestMatch(custom, slug); ok {
			return cp.Input, cp.Output, true
		}
	}
	if registry != nil {
		for _, slug := range candidates {
			if cp, ok := BestMatch(registry.Overrides, slug); ok {
				return cp.Input, cp.Output, true
			}
		}
	}
	if resolver == nil || provider == "" {
		return 0, 0, false
	}
	for _, slug := range candidates {
		price := resolver.Resolve(ctx, provider, slug)
		if !price.Found {
			continue
		}
		in, out := price.InputPrice, price.OutputPrice
		if registry != nil && registry.Discount > 0 {
			factor := 1 - registry.Discount
			in *= factor
			out *= factor
		}
		return in, out, true
	}
	return 0, 0, false
}

// Per1k converts a per-token rate to a per-1000-token rate.
func Per1k(perToken float64) float64 {
	return perToken * 1000
}

// MicroUSD converts a USD amount to micro-USD, rounding half away from zero.
func MicroUSD(costUSD float64) int64 {
	return int64(math.Round(costUSD * 1e6))
}
