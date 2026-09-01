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
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

const (
	// liveModelsCacheTTL keeps one provider round trip out of every model picker
	// render while still noticing a rotated or re-scoped key within minutes.
	liveModelsCacheTTL = 10 * time.Minute
	// liveModelsTimeout bounds the provider GET so a slow provider cannot hold
	// the admin API request open.
	liveModelsTimeout = 8 * time.Second
)

// LiveAvailabilityFilter narrows a catalog listing to the models a registry's
// credentials can actually use, by asking the provider's authenticated models
// endpoint (the static models.dev catalog cannot see org-restricted API keys,
// Azure deployments, or account-gated models).
//
// It never returns an error and degrades to the input on any doubt: a missing
// registry, unsupported provider, listing failure, or an intersection that
// comes back empty (more likely an id mismatch than a key that can invoke
// nothing) all yield the catalog unchanged — a too-long list fails at request
// time with a real provider message, a spuriously empty picker is a dead end.
//
//go:generate mockery --name=LiveAvailabilityFilter --dir=. --output=./mocks --filename=catalog_live_availability_filter_mock.go --case=underscore --with-expecter
type LiveAvailabilityFilter interface {
	Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model
}

var _ LiveAvailabilityFilter = (*liveAvailabilityFilter)(nil)

type liveAvailabilityFilter struct {
	finder  appregistry.Finder
	locator factory.ProviderLocator
	cache   *cache.TTLMap
	logger  *slog.Logger
}

func NewLiveAvailabilityFilter(
	finder appregistry.Finder,
	locator factory.ProviderLocator,
	logger *slog.Logger,
) LiveAvailabilityFilter {
	return &liveAvailabilityFilter{
		finder:  finder,
		locator: locator,
		cache:   cache.NewTTLMap(liveModelsCacheTTL),
		logger:  logger,
	}
}

func (f *liveAvailabilityFilter) Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model {
	// Bedrock availability is owned by the ServerlessFilter (control-plane
	// entitlement checks); everything else resolves through the provider's
	// authenticated models endpoint.
	if in.ProviderCode == providers.ProviderBedrock || len(in.Models) == 0 {
		return in.Models
	}
	if in.GatewayID.IsNil() || in.RegistryID.IsNil() {
		return in.Models
	}

	if _, err := f.locator.GetModelLister(in.ProviderCode); err != nil {
		return in.Models
	}

	reg, err := f.finder.FindByID(ctx, in.GatewayID, in.RegistryID)
	if err != nil {
		f.debugSkip(in, "find registry", err)
		return in.Models
	}
	if reg.Provider() != in.ProviderCode {
		f.debugSkip(in, "registry provider mismatch", nil)
		return in.Models
	}
	auth := reg.Auth()
	if auth == nil || auth.Type == registrydomain.AuthTypeOAuth2 {
		f.debugSkip(in, "unsupported auth for live listing", nil)
		return in.Models
	}

	cfg := &providers.Config{
		Options:     reg.ProviderOptions(),
		Credentials: providers.CredentialsFromTargetAuth(auth),
	}

	live, err := f.liveModels(ctx, in.ProviderCode, auth, cfg)
	if err != nil {
		f.logger.Warn("live model listing failed, listing unfiltered catalog",
			slog.String("provider", in.ProviderCode),
			slog.String("registry_id", in.RegistryID.String()),
			slog.String("error", err.Error()))
		return in.Models
	}
	if len(live) == 0 {
		f.debugSkip(in, "provider reported no models", nil)
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

	// Empty here cannot be told apart from a catalog-vs-provider naming
	// mismatch, so degrade to the full catalog instead of a dead-end picker.
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

func (f *liveAvailabilityFilter) liveModels(
	ctx context.Context,
	providerCode string,
	auth *registrydomain.TargetAuth,
	cfg *providers.Config,
) ([]providers.LiveModel, error) {
	key := liveModelsCacheKey(providerCode, auth, cfg.Options)
	if cached, ok := f.cache.Get(key); ok {
		if live, ok := cached.([]providers.LiveModel); ok {
			return live, nil
		}
	}

	lister, err := f.locator.GetModelLister(providerCode)
	if err != nil {
		return nil, err
	}

	listCtx, cancel := context.WithTimeout(ctx, liveModelsTimeout)
	defer cancel()

	live, err := lister.ListLiveModels(listCtx, cfg)
	if err != nil {
		return nil, err
	}
	f.cache.Set(key, live)
	return live, nil
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

// liveModelsCacheKey scopes a cached listing to the exact credentials and
// provider options, so rotating or re-scoping a key stops serving the previous
// key's availability. Secrets are only ever hashed, never stored or logged.
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
