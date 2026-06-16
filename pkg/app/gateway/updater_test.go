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

	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.ID == id && g.Name == "new" && g.Status == "paused"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	updater := appgateway.NewUpdater(repo, mgr, cachetest.NoopPublisher(), nil, newTestLogger())

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:     id,
		Name:   ptr("new"),
		Status: ptr("paused"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" || got.Status != "paused" {
		t.Fatalf("unexpected gateway: %+v", got)
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String())
	if !ok {
		t.Fatal("updated gateway was not refreshed in cache")
	}
	if cached.(*domain.Gateway).Name != "new" {
		t.Fatal("cache holds stale name after update")
	}
}

func TestUpdater_UpdateSlug_InvalidatesOldSlugCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.RehydrateWithSlug(id, "old", "old", "active", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Slug == "new"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.GatewayTTLName).Set("slug:old", existing)
	updater := appgateway.NewUpdater(repo, mgr, cachetest.NoopPublisher(), nil, newTestLogger())

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Slug: ptr("new"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Slug != "new" {
		t.Fatalf("Slug = %q, want new", got.Slug)
	}
	if _, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("slug:old"); ok {
		t.Fatal("old slug cache key was not invalidated")
	}
	if _, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("slug:new"); !ok {
		t.Fatal("new slug cache key was not populated")
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), nil, newTestLogger())
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Name: ptr("x"),
	})
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdater_Update_Partial_PreservesStatus(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "paused", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Name == "renamed" && g.Status == "paused"
		})).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), nil, newTestLogger())
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Name: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Status != "paused" {
		t.Fatalf("Status = %q, want preserved paused", got.Status)
	}
}

func TestUpdater_Update_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	// repo.Update must not be called.

	updater := appgateway.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), nil, newTestLogger())
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Name: ptr(""),
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}
