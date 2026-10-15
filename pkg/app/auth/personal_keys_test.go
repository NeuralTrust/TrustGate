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
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const day = 24 * time.Hour

var (
	personalNow   = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	personalLimit = time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC)
	errStore      = errors.New("store unavailable")
)

type personalKeysFixture struct {
	gwID       ids.GatewayID
	repo       *repomocks.Repository
	consumers  *consumermocks.Repository
	linkReader *consumermocks.LinkReader
	gateways   *gatewaymocks.Repository
	publisher  *cachemocks.EventPublisher
	signaler   *configsynctest.FakeSignaler
	keyCache   *cache.TTLMap
	keys       appauth.PersonalKeys
}

func newPersonalKeysFixture(t *testing.T) *personalKeysFixture {
	t.Helper()
	manager := newCacheManager()
	f := &personalKeysFixture{
		gwID:       ids.New[ids.GatewayKind](),
		repo:       repomocks.NewRepository(t),
		consumers:  consumermocks.NewRepository(t),
		linkReader: consumermocks.NewLinkReader(t),
		gateways:   gatewaymocks.NewRepository(t),
		publisher:  cachemocks.NewEventPublisher(t),
		signaler:   &configsynctest.FakeSignaler{},
		keyCache:   manager.GetTTLMap(cache.AuthKeyTTLName),
	}
	logger := newTestLogger()
	clock := func() time.Time { return personalNow }
	rotator := appauth.NewRotator(f.repo, manager, f.publisher, logger, f.signaler, clock)
	deleter := appauth.NewDeleter(f.repo, f.consumers, manager, f.publisher, logger, f.signaler)
	f.keys = appauth.NewPersonalKeys(f.repo, f.linkReader, f.gateways, rotator, deleter, appauth.NewKeyEvents(manager, f.publisher, logger, f.signaler), clock)
	return f
}

func (f *personalKeysFixture) gateway(dataPlane string) {
	f.gateways.EXPECT().FindByID(mock.Anything, f.gwID).
		Return(&gatewaydomain.Gateway{ID: f.gwID, Entitlements: gatewaydomain.Entitlements{DataPlane: dataPlane}}, nil).Once()
}

func (f *personalKeysFixture) published() {
	f.publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: f.gwID.String()}).Return(nil).Once()
}

func (f *personalKeysFixture) noKey(owner string) {
	f.repo.EXPECT().FindByOwner(mock.Anything, f.gwID, owner).Return(nil, domain.ErrNotFound).Once()
}

func (f *personalKeysFixture) existingKey(t *testing.T) *domain.Auth {
	t.Helper()
	a, err := domain.NewOwnedAPIKeyAuth(f.gwID, "alice", personalNow.Add(5*day), personalNow)
	require.NoError(t, err)
	f.repo.EXPECT().FindByOwner(mock.Anything, f.gwID, "alice").Return(a, nil).Once()
	return a
}

func (f *personalKeysFixture) links(authID ids.AuthID, n int) []ids.ConsumerID {
	consumerIDs := make([]ids.ConsumerID, 0, n)
	for range n {
		consumerIDs = append(consumerIDs, ids.New[ids.ConsumerKind]())
	}
	f.linkReader.EXPECT().ListIDsByAuthID(mock.Anything, authID).Return(consumerIDs, nil).Once()
	return consumerIDs
}

func (f *personalKeysFixture) listingFails(authID ids.AuthID) {
	f.linkReader.EXPECT().ListIDsByAuthID(mock.Anything, authID).Return(nil, errStore).Once()
}

func TestPersonalKeys_Create_FirstKey(t *testing.T) {
	t.Parallel()
	f := newPersonalKeysFixture(t)
	f.gateway(gatewaydomain.DataPlaneHosted)
	f.noKey("alice")
	f.repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.OwnerID == "alice" && a.OwnerEmail == "alice@acme.test"
	})).Return(nil).Once()
	f.published()

	key, err := f.keys.Create(context.Background(), f.gwID, appauth.PersonalKeyOwner{ID: "alice", Email: " alice@acme.test"}, personalLimit)
	require.NoError(t, err)
	require.NotEmpty(t, key.Auth.RawKey)
	require.Equal(t, domain.HashAPIKey(key.Auth.RawKey), key.Auth.KeyHash)
	require.NotNil(t, key.ConsumerIDs)
	require.Empty(t, key.ConsumerIDs)
	require.True(t, key.Auth.Enabled)
	require.True(t, key.Auth.ExpiresAt.Equal(personalLimit))
	_, cached := f.keyCache.Get(key.Auth.KeyHash)
	require.True(t, cached)
	require.Equal(t, 1, f.signaler.Count())
}

func TestPersonalKeys_Create_Refused(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		owner     string
		email     string
		expiresAt time.Time
		setup     func(t *testing.T, f *personalKeysFixture)
		want      error
	}{
		"no expiry":           {owner: "alice", want: domain.ErrOwnedExpiry},
		"expiry at now":       {owner: "alice", expiresAt: personalNow, want: domain.ErrOwnedExpiry},
		"expiry past 90 days": {owner: "alice", expiresAt: personalLimit.Add(time.Second), want: domain.ErrOwnedExpiry},
		"blank owner":         {owner: " ", expiresAt: personalLimit, want: domain.ErrInvalidOwner},
		"not an email":        {owner: "alice", email: "alice at acme", expiresAt: personalLimit, want: domain.ErrInvalidOwnerEmail},
		"hybrid gateway":      {owner: "alice", expiresAt: personalLimit, want: consumerdomain.ErrHybridPersonal, setup: func(_ *testing.T, f *personalKeysFixture) { f.gateway(gatewaydomain.DataPlaneHybrid) }},
		"second key":          {owner: "alice", expiresAt: personalLimit, want: domain.ErrOwnedKeyExists, setup: func(t *testing.T, f *personalKeysFixture) { f.gateway(""); f.existingKey(t) }},
		"concurrent create 409": {owner: "alice", expiresAt: personalLimit, want: domain.ErrOwnedKeyExists, setup: func(_ *testing.T, f *personalKeysFixture) {
			f.gateway("")
			f.noKey("alice")
			f.repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrOwnedKeyExists).Once()
		}},
		"gateway lookup fails": {owner: "alice", expiresAt: personalLimit, want: errStore, setup: func(_ *testing.T, f *personalKeysFixture) {
			f.gateways.EXPECT().FindByID(mock.Anything, f.gwID).Return(nil, errStore).Once()
		}},
		"owner lookup fails": {owner: "alice", expiresAt: personalLimit, want: errStore, setup: func(_ *testing.T, f *personalKeysFixture) {
			f.gateway("")
			f.repo.EXPECT().FindByOwner(mock.Anything, f.gwID, "alice").Return(nil, errStore).Once()
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			_, err := f.keys.Create(context.Background(), f.gwID, appauth.PersonalKeyOwner{ID: tc.owner, Email: tc.email}, tc.expiresAt)
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, f.signaler.Count())
		})
	}
}

func TestPersonalKeys_Rotate(t *testing.T) {
	t.Parallel()
	at := func(d time.Duration) *time.Time { v := personalNow.Add(d); return &v }
	for name, tc := range map[string]struct {
		expired       bool
		request, want *time.Time
	}{
		"new expiry at the cap":           {request: at(domain.MaxOwnedKeyLifetime), want: at(domain.MaxOwnedKeyLifetime)},
		"absent keeps the current expiry": {want: at(5 * day)},
		"an expired key takes a new one":  {expired: true, request: at(30 * day), want: at(30 * day)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			existing := f.existingKey(t)
			if tc.expired {
				existing.ExpiresAt = at(-day)
			}
			id, oldKey, oldHash := existing.ID, existing.RawKey, existing.KeyHash
			consumerIDs := f.links(id, 2)
			f.repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
			f.repo.EXPECT().RotateKey(mock.Anything, existing, mock.Anything).Return(nil).Once()
			f.published()
			f.keyCache.Set(oldHash, existing)

			key, err := f.keys.Rotate(context.Background(), f.gwID, "alice", tc.request)
			require.NoError(t, err)
			require.Equal(t, id, key.Auth.ID)
			require.Equal(t, consumerIDs, key.ConsumerIDs)
			require.NotEqual(t, oldKey, key.Auth.RawKey)
			require.True(t, key.Auth.ExpiresAt.Equal(*tc.want))
			require.True(t, key.Auth.UpdatedAt.Equal(personalNow))
			_, stale := f.keyCache.Get(oldHash)
			require.False(t, stale)
			require.Equal(t, 1, f.signaler.Count())
		})
	}
}

func TestPersonalKeys_Rotate_Refused(t *testing.T) {
	t.Parallel()
	at := func(d time.Duration) *time.Time { v := personalNow.Add(d); return &v }
	for name, tc := range map[string]struct {
		request *time.Time
		setup   func(t *testing.T, f *personalKeysFixture)
		want    error
	}{
		"expiry beyond the cap": {request: at(domain.MaxOwnedKeyLifetime + time.Second), want: domain.ErrOwnedExpiry},
		"expiry in the past":    {request: at(-time.Hour), want: domain.ErrOwnedExpiry},
		"an expired key without a new expiry": {want: domain.ErrOwnedExpiry, setup: func(t *testing.T, f *personalKeysFixture) {
			existing := f.existingKey(t)
			existing.ExpiresAt = at(-day)
			f.links(existing.ID, 1)
		}},
		"consumer listing fails": {request: at(30 * day), want: errStore, setup: func(t *testing.T, f *personalKeysFixture) {
			f.listingFails(f.existingKey(t).ID)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			_, err := f.keys.Rotate(context.Background(), f.gwID, "alice", tc.request)
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, f.signaler.Count())
		})
	}
}

func TestPersonalKeys_Get(t *testing.T) {
	t.Parallel()
	for name, n := range map[string]int{"unlinked": 0, "linked to two consumers": 2} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			existing := f.existingKey(t)
			existing.RawKey = ""
			consumerIDs := f.links(existing.ID, n)

			key, err := f.keys.Get(context.Background(), f.gwID, "alice")
			require.NoError(t, err)
			require.Equal(t, existing.ID, key.Auth.ID)
			require.Empty(t, key.Auth.RawKey)
			require.NotNil(t, key.ConsumerIDs)
			require.ElementsMatch(t, consumerIDs, key.ConsumerIDs)
		})
	}
}

func TestPersonalKeys_Get_ConsumerListingFails(t *testing.T) {
	t.Parallel()
	f := newPersonalKeysFixture(t)
	f.listingFails(f.existingKey(t).ID)
	_, err := f.keys.Get(context.Background(), f.gwID, "alice")
	require.ErrorIs(t, err, errStore)
}

func TestPersonalKeys_WithoutAKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, op := range map[string]func(appauth.PersonalKeys, ids.GatewayID, string) error{
		"get": func(k appauth.PersonalKeys, gw ids.GatewayID, owner string) error {
			_, err := k.Get(ctx, gw, owner)
			return err
		},
		"rotate": func(k appauth.PersonalKeys, gw ids.GatewayID, owner string) error {
			_, err := k.Rotate(ctx, gw, owner, nil)
			return err
		},
		"revoke": func(k appauth.PersonalKeys, gw ids.GatewayID, owner string) error { return k.Revoke(ctx, gw, owner) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			f.noKey("bob")
			require.ErrorIs(t, op(f.keys, f.gwID, "bob"), commonerrors.ErrNotFound)
			require.ErrorIs(t, op(f.keys, f.gwID, ""), domain.ErrInvalidOwner)
			require.Zero(t, f.signaler.Count())
		})
	}
}

func TestPersonalKeys_RevokeThenCreate(t *testing.T) {
	t.Parallel()
	f := newPersonalKeysFixture(t)
	existing := f.existingKey(t)
	f.repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	f.repo.EXPECT().DeleteOwned(mock.Anything, f.gwID, existing.ID).Return(nil).Once()
	f.published()
	f.keyCache.Set(existing.KeyHash, existing)

	require.NoError(t, f.keys.Revoke(context.Background(), f.gwID, "alice"))
	_, cached := f.keyCache.Get(existing.KeyHash)
	require.False(t, cached)

	f.gateway(gatewaydomain.DataPlaneHosted)
	f.noKey("alice")
	f.repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	f.published()
	key, err := f.keys.Create(context.Background(), f.gwID, appauth.PersonalKeyOwner{ID: "alice"}, personalLimit)
	require.NoError(t, err)
	require.NotEqual(t, existing.ID, key.Auth.ID)
	require.Empty(t, key.ConsumerIDs)
	require.Equal(t, 2, f.signaler.Count())
}

func TestPersonalKeys_RotateAndRevoke_FailuresChangeNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, tc := range map[string]struct {
		run func(t *testing.T, f *personalKeysFixture, existing *domain.Auth) error
	}{
		"rotate when the update fails": {run: func(_ *testing.T, f *personalKeysFixture, existing *domain.Auth) error {
			f.links(existing.ID, 1)
			f.repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			f.repo.EXPECT().RotateKey(mock.Anything, existing, mock.Anything).Return(errStore).Once()
			_, err := f.keys.Rotate(ctx, f.gwID, "alice", nil)
			return err
		}},
		"revoke when the delete fails": {run: func(_ *testing.T, f *personalKeysFixture, existing *domain.Auth) error {
			f.repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			f.repo.EXPECT().DeleteOwned(mock.Anything, f.gwID, existing.ID).Return(errStore).Once()
			return f.keys.Revoke(ctx, f.gwID, "alice")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPersonalKeysFixture(t)
			existing := f.existingKey(t)
			oldHash := existing.KeyHash
			cached := *existing
			f.keyCache.Set(oldHash, &cached)

			require.ErrorIs(t, tc.run(t, f, existing), errStore)
			entry, ok := f.keyCache.Get(oldHash)
			require.True(t, ok, "the old key's cache entry must survive a failed write")
			require.Same(t, &cached, entry)
			require.Equal(t, oldHash, cached.KeyHash)
			require.Zero(t, f.signaler.Count())
			f.publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
		})
	}
}

func TestPersonalKeys_NilClockReadsUTCNow(t *testing.T) {
	t.Parallel()
	manager := newCacheManager()
	repo := repomocks.NewRepository(t)
	gateways := gatewaymocks.NewRepository(t)
	publisher := cachemocks.NewEventPublisher(t)
	gwID := ids.New[ids.GatewayKind]()
	gateways.EXPECT().FindByID(mock.Anything, gwID).Return(&gatewaydomain.Gateway{ID: gwID}, nil).Once()
	repo.EXPECT().FindByOwner(mock.Anything, gwID, "alice").Return(nil, domain.ErrNotFound).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
	logger := newTestLogger()
	keys := appauth.NewPersonalKeys(repo, consumermocks.NewLinkReader(t), gateways,
		appauth.NewRotator(repo, manager, publisher, logger, nil, nil), appauth.NewDeleter(repo, consumermocks.NewRepository(t), manager, publisher, logger, nil),
		appauth.NewKeyEvents(manager, publisher, logger, nil), nil)

	before := time.Now().UTC()
	key, err := keys.Create(context.Background(), gwID, appauth.PersonalKeyOwner{ID: "alice"}, before.Add(day))
	require.NoError(t, err)
	require.Equal(t, time.UTC, key.Auth.CreatedAt.Location())
	require.False(t, key.Auth.CreatedAt.Before(before))
}
