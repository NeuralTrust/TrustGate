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
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

const slugMissTTL = 5 * time.Second

type slugMiss struct {
	at time.Time
}

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=gateway_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error)
	FindBySlug(ctx context.Context, slug string) (*domain.Gateway, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error)
}

var _ Finder = (*finder)(nil)

type finder struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Finder {
	return &finder{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.GatewayTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, id ids.GatewayID) (*domain.Gateway, error) {
	if g, ok := f.cached(gatewayIDCacheKey(id), "gateway_id", id.String()); ok {
		return g, nil
	}
	g, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	setGatewayCache(f.memoryCache, g)
	return g, nil
}

func (f *finder) FindBySlug(ctx context.Context, slug string) (*domain.Gateway, error) {
	slug = domain.NormalizeSlug(slug)
	key := gatewaySlugCacheKey(slug)
	if f.missedRecently(key) {
		return nil, domain.ErrNotFound
	}
	if g, ok := f.cached(key, "gateway_slug", slug); ok {
		return g, nil
	}
	g, err := f.repo.FindBySlug(ctx, slug)
	if errors.Is(err, domain.ErrNotFound) {
		f.memoryCache.Set(key, slugMiss{at: time.Now()})
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	setGatewayCache(f.memoryCache, g)
	return g, nil
}

func (f *finder) missedRecently(key string) bool {
	cached, ok := f.memoryCache.Get(key)
	if !ok {
		return false
	}
	miss, ok := cached.(slugMiss)
	if !ok {
		return false
	}
	if time.Since(miss.at) < slugMissTTL {
		return true
	}
	f.memoryCache.Delete(key)
	return false
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
