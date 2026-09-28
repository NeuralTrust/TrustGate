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
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
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

func TestAPIKeyFinder_ExpiredKey_IsRefused(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	rawKey := "ag_expired"
	hash := domain.HashAPIKey(rawKey)
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	expired := &domain.Auth{ID: ids.New[ids.AuthKind](), Type: domain.TypeAPIKey, Enabled: true, KeyHash: hash, ExpiresAt: &yesterday}
	repo.EXPECT().FindByAPIKeyHash(mock.Anything, hash).Return(expired, nil).Once()

	finder := appauth.NewAPIKeyFinder(repo, newCacheManager(), newTestLogger())
	if _, err := finder.FindByAPIKey(context.Background(), rawKey); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// The expiry travels with the cached entry, so a key that expires while it is
// cached is refused without waiting for the entry to fall out.
func TestAPIKeyFinder_ExpiredWhileCached_IsRefused(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t) // no expectations: the cache answers
	rawKey := "ag_cached-expired"
	hash := domain.HashAPIKey(rawKey)
	justNow := time.Now().UTC().Add(-time.Second)
	cached := &domain.Auth{ID: ids.New[ids.AuthKind](), Type: domain.TypeAPIKey, Enabled: true, KeyHash: hash, ExpiresAt: &justNow}

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.AuthKeyTTLName).Set(hash, cached)

	finder := appauth.NewAPIKeyFinder(repo, mgr, newTestLogger())
	// commonerrors.ErrNotFound, not the auth package's own: what matters is that
	// the funnel answers an expired key exactly as it answers an unknown one.
	if _, err := finder.FindByAPIKey(context.Background(), rawKey); !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want a refusal indistinguishable from an unknown key", err)
	}
}

func TestAPIKeyFinder_KeyWithTimeLeft_IsServed(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	rawKey := "ag_still-good"
	hash := domain.HashAPIKey(rawKey)
	tomorrow := time.Now().UTC().Add(24 * time.Hour)
	want := &domain.Auth{ID: ids.New[ids.AuthKind](), Type: domain.TypeAPIKey, Enabled: true, KeyHash: hash, ExpiresAt: &tomorrow}
	repo.EXPECT().FindByAPIKeyHash(mock.Anything, hash).Return(want, nil).Once()

	finder := appauth.NewAPIKeyFinder(repo, newCacheManager(), newTestLogger())
	got, err := finder.FindByAPIKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("FindByAPIKey: %v", err)
	}
	if got != want {
		t.Fatal("a key with time left must be served")
	}
}
