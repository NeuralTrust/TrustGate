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

package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	// repo.FindByID must NOT be called when cache hits.

	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	mgr := newCacheManager()
	cached := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), cached)

	finder := appgateway.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != cached {
		t.Fatal("FindByID returned a different pointer than the cached entry")
	}
}

func TestFinder_FindByID_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	fromDB := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(fromDB, nil).Once()

	mgr := newCacheManager()
	finder := appgateway.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != fromDB {
		t.Fatal("FindByID did not return the entity loaded from the repository")
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String())
	if !ok {
		t.Fatal("cache was not populated after DB load")
	}
	if cached.(*domain.Gateway) != fromDB {
		t.Fatal("cached pointer does not match the entity returned by the repository")
	}
	slugCached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("slug:" + fromDB.Slug)
	if !ok || slugCached.(*domain.Gateway) != fromDB {
		t.Fatal("slug cache was not populated after DB load")
	}
}

func TestFinder_FindBySlug_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	fromDB := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindBySlug(mock.Anything, "prod").Return(fromDB, nil).Once()

	mgr := newCacheManager()
	finder := appgateway.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindBySlug(context.Background(), "PROD")
	if err != nil {
		t.Fatalf("FindBySlug error: %v", err)
	}
	if got != fromDB {
		t.Fatal("FindBySlug did not return the entity loaded from the repository")
	}
	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("slug:prod")
	if !ok || cached.(*domain.Gateway) != fromDB {
		t.Fatal("slug cache was not populated after DB load")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	finder := appgateway.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFinder_FindByID_PoisonedCache_FallsBackToDB(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	fromDB := domain.Rehydrate(id, "prod", "active", "", nil, nil, nil, now, now)
	repo.EXPECT().FindByID(mock.Anything, id).Return(fromDB, nil).Once()

	mgr := newCacheManager()
	// Wrong type stored under the key — finder must drop it and load
	// from the DB rather than serving garbage.
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), "not a gateway")

	finder := appgateway.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("FindByID error: %v", err)
	}
	if got != fromDB {
		t.Fatal("finder did not fall back to the database on poisoned cache")
	}
	cached, _ := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String())
	if _, ok := cached.(*domain.Gateway); !ok {
		t.Fatal("cache was not refreshed with a proper entity after poison fallback")
	}
}

func TestFinder_List_Passthrough(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	filter := domain.ListFilter{SlugContains: "prod", Page: 1, Size: 20}
	now := time.Now().UTC()
	items := []*domain.Gateway{
		domain.Rehydrate(ids.New[ids.GatewayKind](), "prod-eu", "active", "", nil, nil, nil, now, now),
		domain.Rehydrate(ids.New[ids.GatewayKind](), "prod-us", "active", "", nil, nil, nil, now, now),
	}
	repo.EXPECT().List(mock.Anything, filter).Return(items, 2, nil).Once()

	finder := appgateway.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := finder.List(context.Background(), filter)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("unexpected list result: total=%d items=%d", total, len(got))
	}
}
