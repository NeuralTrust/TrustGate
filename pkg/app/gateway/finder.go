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

package gateway

import (
	"context"
	"errors"
	"log/slog"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error)
	FindBySlug(ctx context.Context, slug string) (*domain.Gateway, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error)
}

var _ Finder = (*finder)(nil)

// finder serves gateways from memoryCache and remembers, in missCache, the ids
// and slugs the repository did not have. A miss lives for the miss map's short
// TTL, which bounds how long a gateway created or renamed on another replica
// can still answer not found here; on this replica the gateway is cached under
// the same key and wins, because memoryCache is read first. A data plane drops
// its misses with every other cache when it applies a config-sync snapshot.
type finder struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	missCache   *cache.TTLMap
	logger      *slog.Logger
}

func NewFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Finder {
	return &finder{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		missCache:   manager.GetTTLMap(cache.GatewayMissTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error) {
	key := gatewayIDCacheKey(id)
	if g, ok := f.cached(key, "gateway_id", id.String()); ok {
		return g, nil
	}
	if f.missedRecently(key) {
		return nil, domain.ErrNotFound
	}
	return f.load(key, func() (*domain.Gateway, error) {
		return f.repo.FindByID(ctx, id)
	})
}

func (f *finder) FindBySlug(ctx context.Context, slug string) (*domain.Gateway, error) {
	slug = domain.NormalizeSlug(slug)
	key := gatewaySlugCacheKey(slug)
	if g, ok := f.cached(key, "gateway_slug", slug); ok {
		return g, nil
	}
	if f.missedRecently(key) {
		return nil, domain.ErrNotFound
	}
	// The gateways table only holds slugs that pass IsValidSlug (a CHECK with
	// the same pattern), so anything else is answered without a query and is
	// not remembered: callers pass request headers straight through, and an
	// 8 KB header must not become an 8 KB miss key. Checked after the miss map,
	// which never holds an invalid slug, so a remembered miss skips the regexp.
	if !domain.IsValidSlug(slug) {
		return nil, domain.ErrNotFound
	}
	return f.load(key, func() (*domain.Gateway, error) {
		return f.repo.FindBySlug(ctx, slug)
	})
}

// load takes the miss map's generation before the read, so a miss found while
// the map was being cleared is not remembered.
func (f *finder) load(key string, read func() (*domain.Gateway, error)) (*domain.Gateway, error) {
	generation := f.missCache.Generation()
	g, err := read()
	if errors.Is(err, domain.ErrNotFound) {
		f.missCache.RememberMiss(key, generation, cache.GatewayMissCacheMaxEntries)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	setGatewayCache(f.memoryCache, g)
	return g, nil
}

func (f *finder) missedRecently(key string) bool {
	_, missed := f.missCache.Get(key)
	return missed
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error) {
	return f.repo.List(ctx, filter)
}

func (f *finder) cached(key, field, value string) (*domain.Gateway, bool) {
	cached, ok := f.memoryCache.Get(key)
	if !ok {
		return nil, false
	}
	g, ok := cached.(*domain.Gateway)
	if ok {
		return g, true
	}
	f.logger.Warn("gateway cache entry failed type assertion; falling back to database",
		slog.String(field, value))
	f.memoryCache.Delete(key)
	return nil, false
}

func setGatewayCache(memoryCache *cache.TTLMap, g *domain.Gateway) {
	memoryCache.Set(gatewayIDCacheKey(g.ID), g)
	if g.Slug != "" {
		memoryCache.Set(gatewaySlugCacheKey(g.Slug), g)
	}
}

func deleteGatewayCache(memoryCache *cache.TTLMap, g *domain.Gateway) {
	if g == nil {
		return
	}
	memoryCache.Delete(gatewayIDCacheKey(g.ID))
	if g.Slug != "" {
		memoryCache.Delete(gatewaySlugCacheKey(g.Slug))
	}
}

func gatewayIDCacheKey(id ids.GatewayID) string {
	return "id:" + id.String()
}

func gatewaySlugCacheKey(slug string) string {
	return "slug:" + domain.NormalizeSlug(slug)
}
