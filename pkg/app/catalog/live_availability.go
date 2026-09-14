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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	providerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"golang.org/x/sync/singleflight"
)

const (
	liveModelsCacheTTL = 10 * time.Minute
	liveModelsTimeout  = 8 * time.Second
	// Source recorded on a model that exists only in the provider's live
	// listing, so a reader can tell it apart from a synced catalog row.
	liveCatalogSource = "live"
)

//go:generate mockery --name=LiveAvailabilityFilter --dir=. --output=./mocks --filename=catalog_live_availability_filter_mock.go --case=underscore --with-expecter
type LiveAvailabilityFilter interface {
	Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model
}

// LiveCatalogLister answers what a registry serves when the stored catalog
// knows nothing about it.
//
// A self-hosted openai_compatible endpoint (and an Azure resource naming its
// own deployments) has no rows in `models_catalog` by design — routing already
// treats those references as unknown rather than absent. A picker cannot: an
// empty list left the model select disabled on a registry whose connection test
// had just listed hundreds of models, with nothing on screen saying why
// (RUN-1552). Listing is only ever additive — it answers when the catalog had
// nothing to say.
//
//go:generate mockery --name=LiveCatalogLister --dir=. --output=./mocks --filename=catalog_live_catalog_lister_mock.go --case=underscore --with-expecter
type LiveCatalogLister interface {
	List(ctx context.Context, in ServerlessFilterInput) []domain.Model
}

type LiveModel struct {
	ID          string
	DisplayName string
}

type LiveModelSource interface {
	Supports(providerCode string) bool
	List(ctx context.Context, providerCode string, auth *registrydomain.TargetAuth, options map[string]any) ([]LiveModel, error)
}

type cachedLiveModels struct {
	models  []LiveModel
	expires time.Time
}

var (
	_ LiveAvailabilityFilter = (*liveAvailabilityFilter)(nil)
	_ LiveCatalogLister      = (*liveAvailabilityFilter)(nil)
)

type liveAvailabilityFilter struct {
	finder appregistry.Finder
	source LiveModelSource
	logger *slog.Logger
	mu     sync.RWMutex
	cache  map[string]cachedLiveModels
	flight singleflight.Group
}

func NewLiveAvailabilityFilter(
	finder appregistry.Finder,
	source LiveModelSource,
	logger *slog.Logger,
) LiveAvailabilityFilter {
	return newLiveCatalog(finder, source, logger)
}

// NewLiveCatalog builds the one instance that both narrows a stored catalog and
// lists a registry that has none, so the two share a cache and a timeout budget.
func NewLiveCatalog(
	finder appregistry.Finder,
	source LiveModelSource,
	logger *slog.Logger,
) (LiveAvailabilityFilter, LiveCatalogLister) {
	live := newLiveCatalog(finder, source, logger)
	return live, live
}

func newLiveCatalog(
	finder appregistry.Finder,
	source LiveModelSource,
	logger *slog.Logger,
) *liveAvailabilityFilter {
	return &liveAvailabilityFilter{
		finder: finder,
		source: source,
		cache:  make(map[string]cachedLiveModels),
		logger: logger,
	}
}

func (f *liveAvailabilityFilter) Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model {
	if in.ProviderCode == providerdomain.Bedrock || len(in.Models) == 0 {
		return in.Models
	}
	if in.GatewayID.IsNil() || in.RegistryID.IsNil() {
		return in.Models
	}

	live, ok := f.listRegistryModels(ctx, in)
	if !ok || len(live) == 0 {
		return in.Models
	}

	liveIDs := make(map[string]struct{}, len(live))
	for _, model := range live {
		liveIDs[strings.ToLower(model.ID)] = struct{}{}
	}

	kept := make([]domain.Model, 0, len(in.Models))
	for _, model := range in.Models {
		if _, ok := liveIDs[strings.ToLower(model.Slug)]; ok {
			kept = append(kept, model)
			continue
		}
		if model.ExternalID != "" {
			if _, ok := liveIDs[strings.ToLower(model.ExternalID)]; ok {
				kept = append(kept, model)
			}
		}
	}

	// An empty intersection may indicate mismatched provider naming.
	if len(kept) == 0 {
		f.logger.Warn("no catalog model matched the provider's live listing, listing unfiltered catalog",
			slog.String("provider", in.ProviderCode),
			slog.String("registry_id", in.RegistryID.String()),
			slog.Int("live_models", len(live)))
		return in.Models
	}

	f.logger.Debug("catalog narrowed to live provider models",
		slog.String("provider", in.ProviderCode),
		slog.String("registry_id", in.RegistryID.String()),
		slog.Int("before", len(in.Models)),
		slog.Int("after", len(kept)))
	return kept
}

// List returns the registry's live models as catalog entries. It answers only
// when the caller has nothing stored: a registry that does resolve against the
// catalog keeps going through Filter, so a listing never widens a catalog the
// gateway already knows.
func (f *liveAvailabilityFilter) List(ctx context.Context, in ServerlessFilterInput) []domain.Model {
	if len(in.Models) > 0 || in.ProviderCode == providerdomain.Bedrock {
		return nil
	}
	if in.GatewayID.IsNil() || in.RegistryID.IsNil() {
		return nil
	}

	live, ok := f.listRegistryModels(ctx, in)
	if !ok || len(live) == 0 {
		return nil
	}

	out := make([]domain.Model, 0, len(live))
	for _, model := range live {
		if model.ID == "" {
			continue
		}
		displayName := model.DisplayName
		if displayName == "" {
			displayName = model.ID
		}
		// Priced and dated by nobody: the gateway has no catalog row for these,
		// and inventing one would put a number on screen that no source backs.
		out = append(out, domain.Model{
			Slug:        model.ID,
			ExternalID:  model.ID,
			DisplayName: displayName,
			Enabled:     true,
			Source:      liveCatalogSource,
		})
	}

	f.logger.Debug("listed the registry's live models for a provider with no catalog",
		slog.String("provider", in.ProviderCode),
		slog.String("registry_id", in.RegistryID.String()),
		slog.Int("models", len(out)))
	return out
}

// listRegistryModels resolves the registry and asks the provider what it
// serves. The bool is false when the question could not be asked at all, which
// every caller reads as "leave the catalog as it is".
func (f *liveAvailabilityFilter) listRegistryModels(
	ctx context.Context,
	in ServerlessFilterInput,
) ([]LiveModel, bool) {
	if f.source == nil || !f.source.Supports(in.ProviderCode) {
		return nil, false
	}

	reg, err := f.finder.FindByID(ctx, in.GatewayID, in.RegistryID)
	if err != nil {
		f.debugSkip(in, "find registry", err)
		return nil, false
	}
	if reg.Provider() != in.ProviderCode {
		f.debugSkip(in, "registry provider mismatch", nil)
		return nil, false
	}
	auth := reg.Auth()
	if auth == nil || auth.Type == registrydomain.AuthTypeOAuth2 {
		f.debugSkip(in, "unsupported auth for live listing", nil)
		return nil, false
	}

	live, err := f.liveModels(ctx, in.ProviderCode, auth, reg.ProviderOptions())
	if err != nil {
		f.logger.Warn("live model listing failed, listing unfiltered catalog",
			slog.String("provider", in.ProviderCode),
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("error", err.Error()))
		return nil, false
	}
	if len(live) == 0 {
		f.debugSkip(in, "provider reported no models", nil)
		return nil, false
	}
	return live, true
}

func (f *liveAvailabilityFilter) liveModels(
	ctx context.Context,
	providerCode string,
	auth *registrydomain.TargetAuth,
	options map[string]any,
) ([]LiveModel, error) {
	key := liveModelsCacheKey(providerCode, auth, options)
	f.mu.RLock()
	cached, ok := f.cache[key]
	f.mu.RUnlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.models, nil
	}
	result := f.flight.DoChan(key, func() (any, error) {
		f.mu.RLock()
		cached, ok := f.cache[key]
		f.mu.RUnlock()
		if ok && time.Now().Before(cached.expires) {
			return cached.models, nil
		}
		listCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), liveModelsTimeout)
		defer cancel()
		models, err := f.source.List(listCtx, providerCode, auth, options)
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		f.cache[key] = cachedLiveModels{models: models, expires: time.Now().Add(liveModelsCacheTTL)}
		f.mu.Unlock()
		return models, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case completed := <-result:
		if completed.Err != nil {
			return nil, completed.Err
		}
		return completed.Val.([]LiveModel), nil
	}
}

func (f *liveAvailabilityFilter) debugSkip(in ServerlessFilterInput, reason string, err error) {
	attrs := []any{
		slog.String("provider", in.ProviderCode),
		slog.String("registry_id", in.RegistryID.String()),
		slog.String("reason", reason),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	f.logger.Debug("live availability filter skipped", attrs...)
}

func liveModelsCacheKey(providerCode string, auth *registrydomain.TargetAuth, options map[string]any) string {
	digest := sha256.New()
	digest.Write([]byte(providerCode))
	digest.Write([]byte{0})
	if raw, err := json.Marshal(auth); err == nil {
		digest.Write(raw)
	}
	digest.Write([]byte{0})
	if raw, err := json.Marshal(options); err == nil {
		digest.Write(raw)
	}
	return providerCode + "|" + hex.EncodeToString(digest.Sum(nil)[:16])
}
