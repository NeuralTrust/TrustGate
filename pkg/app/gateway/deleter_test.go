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
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/cachetest"
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

	deleter := appgateway.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
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

	deleter := appgateway.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
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

	deleter := appgateway.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), id)
	if !errors.Is(err, commonerrors.ErrHasDependents) {
		t.Fatalf("expected ErrHasDependents, got %v", err)
	}
}
