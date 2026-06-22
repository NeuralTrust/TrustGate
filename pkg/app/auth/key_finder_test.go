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

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func TestAPIKeyFinder_CacheMiss_PopulatesCache(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	rawKey := "ag_raw-key"
	hash := domain.HashAPIKey(rawKey)
	want := &domain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](), Type: domain.TypeAPIKey, Enabled: true, KeyHash: hash}
	repo.EXPECT().FindByAPIKeyHash(mock.Anything, hash).Return(want, nil).Once()

	mgr := newCacheManager()
	finder := appauth.NewAPIKeyFinder(repo, mgr, newTestLogger())

	got, err := finder.FindByAPIKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("FindByAPIKey: %v", err)
	}
	if got != want {
		t.Fatal("FindByAPIKey did not return repo result")
	}
	if _, ok := mgr.GetTTLMap(cache.AuthKeyTTLName).Get(hash); !ok {
		t.Fatal("cache was not populated on miss")
	}
}

func TestAPIKeyFinder_CacheHit_SkipsRepo(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t) // no expectations: repo must not be called
	rawKey := "ag_cached-key"
	hash := domain.HashAPIKey(rawKey)
	cached := &domain.Auth{ID: ids.New[ids.AuthKind](), Type: domain.TypeAPIKey, Enabled: true, KeyHash: hash}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.AuthKeyTTLName).Set(hash, cached)

	finder := appauth.NewAPIKeyFinder(repo, mgr, newTestLogger())
	got, err := finder.FindByAPIKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("FindByAPIKey: %v", err)
	}
	if got != cached {
		t.Fatal("FindByAPIKey did not return the cached instance")
	}
}

func TestAPIKeyFinder_NotFound_Propagates(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	rawKey := "ag_missing"
	repo.EXPECT().FindByAPIKeyHash(mock.Anything, domain.HashAPIKey(rawKey)).Return(nil, domain.ErrNotFound).Once()

	finder := appauth.NewAPIKeyFinder(repo, newCacheManager(), newTestLogger())
	if _, err := finder.FindByAPIKey(context.Background(), rawKey); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
