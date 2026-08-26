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
	"errors"
	"log/slog"
	"strconv"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"golang.org/x/sync/singleflight"
)

type Pricing struct {
	ModelLabel      string
	InputPrice      float64
	OutputPrice     float64
	CacheReadPrice  float64
	CacheWritePrice float64
	Found           bool
}

//go:generate mockery --name=PricingResolver --dir=. --output=./mocks --filename=pricing_resolver_mock.go --case=underscore --with-expecter
type PricingResolver interface {
	Resolve(ctx context.Context, providerCode, slug string) Pricing
	InvalidateCache()
}

var _ PricingResolver = (*pricingResolver)(nil)

type pricingResolver struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	sf          singleflight.Group
	logger      *slog.Logger
}

func NewPricingResolver(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) PricingResolver {
	return &pricingResolver{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.CatalogModelTTLName),
		logger:      logger,
	}
}

func (r *pricingResolver) Resolve(ctx context.Context, providerCode, slug string) Pricing {
	if providerCode == "" || slug == "" {
		return Pricing{}
	}
	key := providerCode + ":" + slug
	if cached, ok := r.cached(key); ok {
		return cached
	}
	v, _, _ := r.sf.Do(key, func() (interface{}, error) {
		if cached, ok := r.cached(key); ok {
			return cached, nil
		}
		p := r.load(ctx, providerCode, slug)
		if !p.Found && providerCode == providers.ProviderOpenAICompatible {
			p = r.load(ctx, providers.ProviderOpenAI, slug)
		}
		r.memoryCache.Set(key, p)
		return p, nil
	})
	return v.(Pricing)
}

func (r *pricingResolver) InvalidateCache() {
	r.memoryCache.Clear()
}

func (r *pricingResolver) cached(key string) (Pricing, bool) {
	cached, ok := r.memoryCache.Get(key)
	if !ok {
		return Pricing{}, false
	}
	p, ok := cached.(Pricing)
	if !ok {
		r.memoryCache.Delete(key)
		return Pricing{}, false
	}
	return p, true
}

func (r *pricingResolver) load(ctx context.Context, providerCode, slug string) Pricing {
	model, err := r.repo.FindModel(ctx, providerCode, slug)
	if err != nil {
		if !errors.Is(err, commonerrors.ErrNotFound) {
			r.logger.Warn("catalog pricing lookup failed",
				slog.String("provider", providerCode),
				slog.String("model", slug),
				slog.String("error", err.Error()))
		}
		return Pricing{}
	}
	if model.InputPrice == "" && model.OutputPrice == "" {
		return Pricing{}
	}
	input := parsePrice(model.InputPrice)
	return Pricing{
		ModelLabel:      model.DisplayName,
		InputPrice:      input,
		OutputPrice:     parsePrice(model.OutputPrice),
		CacheReadPrice:  coalescePrice(model.CacheReadPrice, input),
		CacheWritePrice: coalescePrice(model.CacheWritePrice, input),
		Found:           true,
	}
}

// coalescePrice reads an unpublished cache rate as "bills at the plain input
// rate", which is what the gateway charged for those tokens before cache rates
// existed. Falling back to zero would silently make most of a cached prompt
// free, which is the worse way to be wrong about money.
func coalescePrice(raw string, fallback float64) float64 {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	return parsePrice(raw)
}

func parsePrice(raw string) float64 {
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return v
}
