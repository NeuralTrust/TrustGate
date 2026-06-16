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

package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func TestFinder_FindByID_CacheHit(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cached := &domain.Auth{ID: id, GatewayID: gwID, Name: "cached"}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.AuthTTLName).Set(id.String(), cached)

	finder := appauth.NewFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got != cached {
		t.Fatal("FindByID did not return cached instance")
	}
}

func TestFinder_FindByID_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	want := &domain.Auth{ID: id, GatewayID: gwID, Name: "from-db"}
	repo.EXPECT().FindByID(mock.Anything, id).Return(want, nil).Once()

	mgr := newCacheManager()
	finder := appauth.NewFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByID(context.Background(), gwID, id)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got != want {
		t.Fatal("FindByID did not return repo result")
	}
	if _, ok := mgr.GetTTLMap(cache.AuthTTLName).Get(id.String()); !ok {
		t.Fatal("cache was not populated on miss")
	}
}

func TestFinder_FindByID_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	finder := appauth.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFinder_FindByID_WrongGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	want := &domain.Auth{ID: id, GatewayID: ids.New[ids.GatewayKind](), Name: "other"}
	repo.EXPECT().FindByID(mock.Anything, id).Return(want, nil).Once()

	finder := appauth.NewFinder(repo, newCacheManager(), newTestLogger())
	_, err := finder.FindByID(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway id", err)
	}
}

func TestFinder_List(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	want := []*domain.Auth{{ID: ids.New[ids.AuthKind](), Name: "a"}}
	repo.EXPECT().
		List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
			return f.NameContains == "a"
		})).
		Return(want, 1, nil).
		Once()

	finder := appauth.NewFinder(repo, newCacheManager(), newTestLogger())
	got, total, err := finder.List(context.Background(), domain.ListFilter{NameContains: "a"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("List returned total=%d len=%d", total, len(got))
	}
}
