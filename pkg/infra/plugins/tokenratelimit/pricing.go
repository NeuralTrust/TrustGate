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

package tokenratelimit

import (
	"context"
	"math"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func (p *Plugin) priceFor(ctx context.Context, cfg *config, provider string, models ...string) (float64, float64, bool) {
	candidates := appcatalog.SlugCandidates(models...)
	for _, slug := range candidates {
		if cp, ok := bestMatch(cfg.CustomPricing, slug); ok {
			return cp.Input, cp.Output, true
		}
	}
	if p.pricing == nil || provider == "" {
		return 0, 0, false
	}
	for _, slug := range candidates {
		price := p.pricing.Resolve(ctx, provider, slug)
		if price.Found {
			return price.InputPrice, price.OutputPrice, true
		}
	}
	return 0, 0, false
}

func per1k(perToken float64) float64 {
	return perToken * 1000
}

func microUSD(costUSD float64) int64 {
	return int64(math.Round(costUSD * 1e6))
}

func billableInputTokens(cfg *config, usage *adapter.CanonicalUsage) int {
	if usage == nil {
		return 0
	}
	in := usage.InputTokens
	if cfg.CountCacheReads {
		in += usage.CacheReadInputTokens
	}
	return in
}
