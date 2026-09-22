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
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func existingAPIKey(t *testing.T, gwID ids.GatewayID) *domain.Auth {
	t.Helper()
	a, err := domain.NewAPIKeyAuth(gwID, "client-key", true, nil)
	require.NoError(t, err)
	return a
}

func TestRotator_Rotate_ReplacesTheSecretAndKeepsTheAuth(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingAPIKey(t, gwID)
	firstKey, firstHash := existing.RawKey, existing.KeyHash

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.ID == existing.ID && a.KeyHash != firstHash
	})).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	manager := newCacheManager()
	keyCache := manager.GetTTLMap(cache.AuthKeyTTLName)
	// The old secret is in the key cache, as it would be after any request that
	// presented it.
	keyCache.Set(firstHash, existing)

	rotated, err := appauth.NewRotator(repo, manager, publisher, newTestLogger(), nil).
		Rotate(context.Background(), appauth.RotateInput{ID: existing.ID, GatewayID: gwID})
	require.NoError(t, err)

	require.NotEqual(t, firstKey, rotated.RawKey, "rotation must mint a new secret")
	require.Equal(t, domain.HashAPIKey(rotated.RawKey), rotated.KeyHash)
	require.Equal(t, existing.ID, rotated.ID, "the auth itself is kept: its id is what consumers hold")
	require.Equal(t, "client-key", rotated.Name)

	// The digest the replaced secret was looked up by is gone, so presenting it
	// falls through to the database and fails there rather than being served
	// from cache until the entry expires.
	_, stillCached := keyCache.Get(firstHash)
	require.False(t, stillCached, "the previous key hash must be evicted")
	_, nowCached := keyCache.Get(rotated.KeyHash)
	require.True(t, nowCached, "the new key hash must be cached")
}

func TestRotator_Rotate_RefusesAnAuthThatIsNotAnAPIKey(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	oauth := existingOAuth2Auth(gwID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, oauth.ID).Return(oauth, nil).Once()

	_, err := appauth.NewRotator(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil).
		Rotate(context.Background(), appauth.RotateInput{ID: oauth.ID, GatewayID: gwID})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
}

func TestRotator_Rotate_RefusesAnAuthOfAnotherGateway(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingAPIKey(t, gwID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	_, err := appauth.NewRotator(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil).
		Rotate(context.Background(), appauth.RotateInput{ID: existing.ID, GatewayID: ids.New[ids.GatewayKind]()})
	require.True(t, errors.Is(err, commonerrors.ErrNotFound))
}
