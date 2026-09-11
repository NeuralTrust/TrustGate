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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
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
			return g.ID == id && g.Slug == "new" && g.Status == "paused"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:     id,
		Slug:   ptr("new"),
		Status: ptr("paused"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Slug != "new" || got.Status != "paused" {
		t.Fatalf("unexpected gateway: %+v", got)
	}

	cached, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String())
	if !ok {
		t.Fatal("updated gateway was not refreshed in cache")
	}
	if cached.(*domain.Gateway).Slug != "new" {
		t.Fatal("cache holds stale slug after update")
	}
}

func TestUpdater_UpdateSlug_InvalidatesOldSlugCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Slug == "new"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.GatewayTTLName).Set("slug:old", existing)
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

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

	publisher := cachemocks.NewEventPublisher(t)

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Slug: ptr("x"),
	})
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
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
			return g.Slug == "renamed" && g.Status == "paused"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Slug: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Status != "paused" {
		t.Fatalf("Status = %q, want preserved paused", got.Status)
	}
}

func TestUpdater_Update_TenantIDIsServerOnlyAndImmutable(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme", "env": "prod"}

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Metadata["env"] == "staging"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:       id,
		Metadata: map[string]string{domain.MetadataTenantIDKey: "globex", "env": "staging"},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.TenantID() != "acme" {
		t.Fatalf("tenant_id mutated by client: got %q, want the immutable acme", got.TenantID())
	}
	if got.Metadata["env"] != "staging" {
		t.Fatalf("non-reserved metadata was not updated: %+v", got.Metadata)
	}
}

func TestUpdater_Update_HealsEmptyTenantFromContext(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{"env": "prod"}

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme" && g.Metadata["env"] == "prod"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:       id,
		TenantID: "acme",
		Slug:     ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.TenantID() != "acme" {
		t.Fatalf("empty tenant_id was not healed from context: got %q, want acme", got.TenantID())
	}
}

func TestUpdater_Update_ContextTenantDoesNotOverrideExisting(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme"}

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TenantID() == "acme"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:       id,
		TenantID: "globex",
		Slug:     ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.TenantID() != "acme" {
		t.Fatalf("existing tenant_id must win over context: got %q, want acme", got.TenantID())
	}
}

func TestUpdater_Update_PersistsEntitlementsWhenProvided(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "standard"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	ent := stampedEntitlements("standard")
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:           id,
		Entitlements: &ent,
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", got.Entitlements.Tier)
	}
}

func TestUpdater_Update_PreservesEntitlementsWhenOmitted(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Entitlements = stampedEntitlements("enterprise")

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "enterprise"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Slug: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Entitlements.Tier != "enterprise" {
		t.Fatalf("Entitlements.Tier = %q, want unchanged enterprise", got.Entitlements.Tier)
	}
}

func TestUpdater_Update_RejectsEntitlementsForTenantCaller(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme"}

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	ent := stampedEntitlements("enterprise")
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:           id,
		TenantID:     "acme",
		Entitlements: &ent,
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected ErrValidation rejecting tenant entitlements, got %v", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_AllowsEntitlementsForPlatformAdmin(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme"}

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "standard"
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	ent := stampedEntitlements("standard")
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:            id,
		TenantID:      "",
		PlatformAdmin: true,
		Entitlements:  &ent,
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Entitlements.Tier != "standard" {
		t.Fatalf("platform entitlements must be honored: got %q, want standard", got.Entitlements.Tier)
	}
}

func TestUpdater_Update_RejectsTierChangeOverInstanceCap(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme"}
	existing.Entitlements = stampedEntitlements("enterprise")

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "free"
		}), "acme", 5).
		Return(ratelimit.ErrInstanceLimit).
		Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, true)
	free := stampedEntitlements("free")
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:            id,
		PlatformAdmin: true,
		Entitlements:  &free,
	})
	if !errors.Is(err, ratelimit.ErrInstanceLimit) {
		t.Fatalf("expected ErrInstanceLimit downgrading over the cap, got %v", err)
	}
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("expected wrapped commonerrors.ErrConflict, got %v", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_AllowsTierChangeWithinInstanceCap(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)
	existing.Metadata = map[string]string{domain.MetadataTenantIDKey: "acme"}
	existing.Entitlements = stampedEntitlements("enterprise")

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.Entitlements.Tier == "free"
		}), "acme", 5).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, true)
	free := stampedEntitlements("free")
	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:            id,
		PlatformAdmin: true,
		Entitlements:  &free,
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Entitlements.Tier != "free" {
		t.Fatalf("Entitlements.Tier = %q, want free", got.Entitlements.Tier)
	}
}

func TestUpdater_Update_RejectsEmptySlug(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "old", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	updater := appgateway.NewUpdater(repo, newCacheManager(), publisher, nil, newTestLogger(), nil, false)
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:   id,
		Slug: ptr(""),
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_StoreModeCuratedThenOpen(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.StoreMode() == domain.StoreModeCurated &&
				g.Metadata[domain.MetadataStoreModeKey] == domain.StoreModeCurated
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:        id,
		StoreMode: ptr(domain.StoreModeCurated),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.StoreMode() != domain.StoreModeCurated {
		t.Fatalf("StoreMode = %q, want curated", got.StoreMode())
	}
}

func TestUpdater_Update_StoreModeNonePersists(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.StoreMode() == domain.StoreModeNone &&
				g.Metadata[domain.MetadataStoreModeKey] == domain.StoreModeNone
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:        id,
		StoreMode: ptr(domain.StoreModeNone),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.StoreMode() != domain.StoreModeNone {
		t.Fatalf("StoreMode = %q, want none", got.StoreMode())
	}
}

func TestUpdater_Update_StoreModeOpenClearsCurated(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
	existing.Metadata = domain.WithStoreMode(nil, domain.StoreModeCurated)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			_, present := g.Metadata[domain.MetadataStoreModeKey]
			return g.StoreMode() == domain.StoreModeOpen && !present
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:        id,
		StoreMode: ptr(domain.StoreModeOpen),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.StoreMode() != domain.StoreModeOpen {
		t.Fatalf("StoreMode = %q, want open", got.StoreMode())
	}
}

func TestUpdater_Update_StoreModePreservedWhenOmitted(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
	existing.Metadata = domain.WithStoreMode(map[string]string{"env": "prod"}, domain.StoreModeCurated)

	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.StoreMode() == domain.StoreModeCurated && g.Metadata["env"] == "prod"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	updater := appgateway.NewUpdater(repo, mgr, publisher, nil, newTestLogger(), nil, false)

	got, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:     id,
		Status: ptr("paused"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.StoreMode() != domain.StoreModeCurated {
		t.Fatalf("StoreMode = %q, want curated preserved", got.StoreMode())
	}
}
