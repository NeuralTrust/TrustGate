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
	appgatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	// Pre-populate the cache: the deleter must wipe it.
	now := time.Now().UTC()
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), domain.Rehydrate(id, "x", "active", "", nil, nil, nil, now, now))

	purger := appgatewaymocks.NewStatePurger(t)
	purger.EXPECT().PurgeGatewayState(mock.Anything, id).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	deleter := appgateway.NewDeleter(repo, mgr, publisher, newTestLogger(), nil, purger)
	if err := deleter.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String()); ok {
		t.Fatal("cache entry was not invalidated after delete")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().Delete(mock.Anything, id).Return(domain.ErrNotFound).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), &domain.Gateway{ID: id})

	// No expectations on the purger or the publisher: a delete the repository
	// refused must neither reap the gateway's credentials nor announce a change.
	purger := appgatewaymocks.NewStatePurger(t)
	publisher := cachemocks.NewEventPublisher(t)

	deleter := appgateway.NewDeleter(repo, mgr, publisher, newTestLogger(), nil, purger)
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	purger.AssertNotCalled(t, "PurgeGatewayState", mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
	// On failure the cache entry is intentionally left untouched —
	// the repo did not change state.
	if _, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String()); !ok {
		t.Fatal("cache entry was wiped on repo failure")
	}
}

func TestDeleter_Delete_HasDependents(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().Delete(mock.Anything, id).Return(domain.ErrHasDependents).Once()

	purger := appgatewaymocks.NewStatePurger(t)
	publisher := cachemocks.NewEventPublisher(t)

	deleter := appgateway.NewDeleter(repo, newCacheManager(), publisher, newTestLogger(), nil, purger)
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrHasDependents) {
		t.Fatalf("expected ErrHasDependents, got %v", err)
	}
	purger.AssertNotCalled(t, "PurgeGatewayState", mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

// A purge failure must not turn a completed delete into an API error: the
// gateway row is already gone and the caller cannot retry it.
func TestDeleter_Delete_SurvivesPurgeFailure(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	purger := appgatewaymocks.NewStatePurger(t)
	purger.EXPECT().PurgeGatewayState(mock.Anything, id).Return(errors.New("redis down")).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(nil).
		Once()

	deleter := appgateway.NewDeleter(repo, newCacheManager(), publisher, newTestLogger(), nil, purger)
	if err := deleter.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete error = %v, want nil despite the purge failure", err)
	}
}

// Same contract for the event bus: the row is gone, so a broker failure only
// costs the other replicas a stale read model until their TTL expires.
func TestDeleter_Delete_SurvivesPublishFailure(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	purger := appgatewaymocks.NewStatePurger(t)
	purger.EXPECT().PurgeGatewayState(mock.Anything, id).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: id.String()}).
		Return(errors.New("redis unreachable")).
		Once()

	mgr := newCacheManager()
	now := time.Now().UTC()
	mgr.GetTTLMap(cache.GatewayTTLName).Set("id:"+id.String(), domain.Rehydrate(id, "x", "active", "", nil, nil, nil, now, now))

	deleter := appgateway.NewDeleter(repo, mgr, publisher, newTestLogger(), nil, purger)
	if err := deleter.Delete(context.Background(), id); err != nil {
		t.Fatalf("Delete error = %v, want nil despite the publish failure", err)
	}
	if _, ok := mgr.GetTTLMap(cache.GatewayTTLName).Get("id:" + id.String()); ok {
		t.Fatal("local cache must be wiped even when the invalidation cannot be broadcast")
	}
}
