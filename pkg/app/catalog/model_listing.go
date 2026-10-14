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
	"log/slog"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"golang.org/x/sync/singleflight"
)

type Verdict int

const (
	VerdictUnknown Verdict = iota
	VerdictListed
	VerdictAbsent
)

const opaqueModelRefPrefix = "arn:"

//go:generate mockery --name=ModelListing --dir=. --output=./mocks --filename=catalog_model_listing_mock.go --case=underscore --with-expecter
type ModelListing interface {
	Lists(ctx context.Context, providerCode, model string) Verdict
	// Capabilities returns the catalog capability flags for a model.
	// known is false when the catalog has no flags for it; callers pass
	// those requests through.
	Capabilities(ctx context.Context, providerCode, model string) (map[string]any, bool)
	InvalidateCache()
}

var _ ModelListing = (*modelListing)(nil)

type listedModels struct {
	slugs        map[string]struct{}
	capabilities map[string]map[string]any
}

type modelListing struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	sf          singleflight.Group
	logger      *slog.Logger
}

func NewModelListing(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) ModelListing {
	return &modelListing{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.CatalogListingTTLName),
		logger:      logger,
	}
}

func (a *modelListing) Lists(ctx context.Context, providerCode, model string) Verdict {
	if a == nil || a.repo == nil {
		return VerdictUnknown
	}
	providerCode = strings.ToLower(strings.TrimSpace(providerCode))
	model = strings.TrimSpace(model)
	if providerCode == "" || model == "" {
		return VerdictUnknown
	}
	if isOpaqueModelRef(model) || providerListingIsNotAuthoritative(providerCode) {
		return VerdictUnknown
	}
	listing := a.listing(ctx, providerCode)
	if len(listing.slugs) == 0 {
		return VerdictUnknown
	}
	if _, found := listing.slugs[strings.ToLower(model)]; found {
		return VerdictListed
	}
	for _, slug := range SlugCandidates(model) {
		if _, found := listing.slugs[strings.ToLower(slug)]; found {
			return VerdictListed
		}
	}
	return VerdictAbsent
}

func (a *modelListing) Capabilities(ctx context.Context, providerCode, model string) (map[string]any, bool) {
	if a == nil || a.repo == nil {
		return nil, false
	}
	providerCode = strings.ToLower(strings.TrimSpace(providerCode))
	model = strings.TrimSpace(model)
	if providerCode == "" || model == "" || isOpaqueModelRef(model) {
		return nil, false
	}
	listing := a.listing(ctx, providerCode)
	if len(listing.slugs) == 0 {
		return nil, false
	}
	if flags, known := listing.capabilityFlags(model); known {
		return flags, true
	}
	for _, slug := range SlugCandidates(model) {
		if flags, known := listing.capabilityFlags(slug); known {
			return flags, true
		}
	}
	return nil, false
}

func (listing listedModels) capabilityFlags(model string) (map[string]any, bool) {
	flags, ok := listing.capabilities[strings.ToLower(model)]
	if !ok || len(flags) == 0 {
		return nil, false
	}
	return flags, true
}

func (a *modelListing) InvalidateCache() {
	a.memoryCache.Clear()
}

func (a *modelListing) listing(ctx context.Context, providerCode string) listedModels {
	if cached, ok := a.cached(providerCode); ok {
		return cached
	}
	v, _, _ := a.sf.Do(providerCode, func() (interface{}, error) {
		if cached, ok := a.cached(providerCode); ok {
			return cached, nil
		}
		listing := a.load(ctx, providerCode)
		a.memoryCache.Set(providerCode, listing)
		return listing, nil
	})
	listing, ok := v.(listedModels)
	if !ok {
		return listedModels{}
	}
	return listing
}

func (a *modelListing) cached(providerCode string) (listedModels, bool) {
	cached, ok := a.memoryCache.Get(providerCode)
	if !ok {
		return listedModels{}, false
	}
	listing, ok := cached.(listedModels)
	if !ok {
		a.memoryCache.Delete(providerCode)
		return listedModels{}, false
	}
	return listing, true
}

func (a *modelListing) load(ctx context.Context, providerCode string) listedModels {
	models, err := a.repo.ListModelsByProviderCode(ctx, providerCode)
	if err != nil {
		a.logger.Warn("catalog listing lookup failed, routing will probe the registry chain",
			slog.String("provider", providerCode),
			slog.String("error", err.Error()))
		return listedModels{}
	}
	slugs := make(map[string]struct{}, len(models))
	capabilities := make(map[string]map[string]any)
	for _, model := range models {
		if !model.Enabled {
			continue
		}
		for _, slug := range SlugCandidates(model.Slug, model.ExternalID) {
			key := strings.ToLower(slug)
			slugs[key] = struct{}{}
			if len(model.Capabilities) == 0 {
				continue
			}
			if _, exists := capabilities[key]; exists {
				continue
			}
			capabilities[key] = model.Capabilities
		}
	}
	return listedModels{slugs: slugs, capabilities: capabilities}
}

func isOpaqueModelRef(model string) bool {
	return strings.HasPrefix(strings.ToLower(model), opaqueModelRefPrefix)
}

func providerListingIsNotAuthoritative(providerCode string) bool {
	switch providerCode {
	case providers.ProviderAzure, providers.ProviderOpenAICompatible:
		return true
	default:
		return false
	}
}
