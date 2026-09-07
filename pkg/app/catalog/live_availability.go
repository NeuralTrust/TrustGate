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
)

//go:generate mockery --name=LiveAvailabilityFilter --dir=. --output=./mocks --filename=catalog_live_availability_filter_mock.go --case=underscore --with-expecter
type LiveAvailabilityFilter interface {
	Filter(ctx context.Context, in ServerlessFilterInput) []domain.Model
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

var _ LiveAvailabilityFilter = (*liveAvailabilityFilter)(nil)

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

	if f.source == nil || !f.source.Supports(in.ProviderCode) {
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

	live, err := f.liveModels(ctx, in.ProviderCode, auth, reg.ProviderOptions())
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
