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

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"golang.org/x/sync/singleflight"
)

type Pricing struct {
	ModelLabel  string
	InputPrice  float64
	OutputPrice float64
	Found       bool
}

//go:generate mockery --name=PricingResolver --dir=. --output=./mocks --filename=pricing_resolver_mock.go --case=underscore --with-expecter
type PricingResolver interface {
	Resolve(ctx context.Context, providerCode, slug string) Pricing
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
		return r.load(ctx, providerCode, slug, key), nil
	})
	return v.(Pricing)
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

func (r *pricingResolver) load(ctx context.Context, providerCode, slug, key string) Pricing {
	model, err := r.repo.FindModel(ctx, providerCode, slug)
	if err != nil {
		if !errors.Is(err, commonerrors.ErrNotFound) {
			r.logger.Warn("catalog pricing lookup failed",
				slog.String("provider", providerCode),
				slog.String("model", slug),
				slog.String("error", err.Error()))
		}
		p := Pricing{}
		r.memoryCache.Set(key, p)
		return p
	}
	p := Pricing{
		ModelLabel:  model.DisplayName,
		InputPrice:  parsePrice(model.InputPrice),
		OutputPrice: parsePrice(model.OutputPrice),
		Found:       true,
	}
	r.memoryCache.Set(key, p)
	return p
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
