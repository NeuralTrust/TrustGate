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
	"github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var issuerNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func issuedKey(gatewayID ids.GatewayID, expiresAt time.Time) *appauth.PersonalKey {
	return &appauth.PersonalKey{Auth: &domain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: gatewayID, OwnerID: "alice",
		RawKey: "ag_secret", ExpiresAt: &expiresAt,
	}}
}

// A key issued outside the console lives as long as the Portal's: the 90-day
// ceiling, less the margin that keeps the request from being refused for
// asking for exactly the limit.
func TestPersonalKeyIssuer_CreatesForTheFullLifetimeWithTheOwnersGroups(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	keys := mocks.NewPersonalKeys(t)
	groups := mocks.NewOwnerGroupsSetter(t)
	want := issuerNow.Add(domain.MaxOwnedKeyLifetime - appauth.PersonalKeyExpiryMargin)
	key := issuedKey(gw, want)
	keys.EXPECT().Create(mock.Anything, gw, "alice", want).Return(key, nil).Once()
	groups.EXPECT().SetOwnerGroups(mock.Anything, appauth.SetOwnerGroupsInput{
		ID: key.Auth.ID, GatewayID: gw, Groups: []string{"eng", "sre"},
	}).Return(&domain.Auth{ID: key.Auth.ID, OwnerGroups: []string{"eng", "sre"}}, nil).Once()

	issuer := appauth.NewPersonalKeyIssuer(keys, groups, nil, func() time.Time { return issuerNow })
	got, err := issuer.Create(context.Background(), gw, "alice", []string{" sre", "eng", "sre"})

	require.NoError(t, err)
	require.Equal(t, "ag_secret", got.Auth.RawKey, "the secret survives the groups write")
	require.Equal(t, []string{"eng", "sre"}, got.Auth.OwnerGroups)
}

// The key exists and its secret is about to be shown once: a failed groups
// write must not cost the person a key they never saw.
func TestPersonalKeyIssuer_KeepsTheKeyWhenItsGroupsCannotBeRecorded(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	keys := mocks.NewPersonalKeys(t)
	groups := mocks.NewOwnerGroupsSetter(t)
	key := issuedKey(gw, issuerNow.Add(time.Hour))
	keys.EXPECT().Create(mock.Anything, gw, "alice", mock.Anything).Return(key, nil).Once()
	groups.EXPECT().SetOwnerGroups(mock.Anything, mock.Anything).Return(nil, errors.New("db down")).Once()

	got, err := appauth.NewPersonalKeyIssuer(keys, groups, nil, nil).Create(context.Background(), gw, "alice", []string{"eng"})

	require.NoError(t, err)
	require.Equal(t, "ag_secret", got.Auth.RawKey)
}

func TestPersonalKeyIssuer_WritesNoGroupsForAnOwnerWithNone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	keys := mocks.NewPersonalKeys(t)
	groups := mocks.NewOwnerGroupsSetter(t)
	keys.EXPECT().Create(mock.Anything, gw, "alice", mock.Anything).Return(issuedKey(gw, issuerNow.Add(time.Hour)), nil).Once()

	_, err := appauth.NewPersonalKeyIssuer(keys, groups, nil, nil).Create(context.Background(), gw, "alice", nil)

	require.NoError(t, err)
}

// As in the Portal: an expired key is rotated into a new full lifetime, a live
// one keeps its expiry.
func TestPersonalKeyIssuer_RenewsOnlyAnExpiredKeyOnRotate(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	clock := func() time.Time { return issuerNow }
	renewed := issuerNow.Add(domain.MaxOwnedKeyLifetime - appauth.PersonalKeyExpiryMargin)

	live := mocks.NewPersonalKeys(t)
	live.EXPECT().Get(mock.Anything, gw, "alice").Return(issuedKey(gw, issuerNow.Add(time.Hour)), nil).Once()
	live.EXPECT().Rotate(mock.Anything, gw, "alice", (*time.Time)(nil)).Return(issuedKey(gw, issuerNow.Add(time.Hour)), nil).Once()
	_, err := appauth.NewPersonalKeyIssuer(live, nil, nil, clock).Rotate(context.Background(), gw, "alice")
	require.NoError(t, err)

	expired := mocks.NewPersonalKeys(t)
	expired.EXPECT().Get(mock.Anything, gw, "alice").Return(issuedKey(gw, issuerNow.Add(-time.Hour)), nil).Once()
	expired.EXPECT().Rotate(mock.Anything, gw, "alice", &renewed).Return(issuedKey(gw, renewed), nil).Once()
	_, err = appauth.NewPersonalKeyIssuer(expired, nil, nil, clock).Rotate(context.Background(), gw, "alice")
	require.NoError(t, err)
}

type chanNotifier chan appauth.PersonalKeyEvent

func (c chanNotifier) Notify(_ context.Context, e appauth.PersonalKeyEvent) error {
	c <- e
	return nil
}

type tenantGateways map[ids.GatewayID]string

func (g tenantGateways) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return &gatewaydomain.Gateway{ID: id, Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: g[id]}}, nil
}

func nextEvent(t *testing.T, events chanNotifier) appauth.PersonalKeyEvent {
	t.Helper()
	select {
	case e := <-events:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("the console was not told")
		return appauth.PersonalKeyEvent{}
	}
}

// The console audits a change and reconciles the key's links when the Portal
// makes it; a change made from the Store is told to it so it does the same.
func TestPersonalKeyIssuer_TellsTheConsoleWhatChanged(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	keys := mocks.NewPersonalKeys(t)
	key := issuedKey(gw, issuerNow.Add(time.Hour))
	keys.EXPECT().Create(mock.Anything, gw, "alice", mock.Anything).Return(key, nil).Once()
	keys.EXPECT().Get(mock.Anything, gw, "alice").Return(key, nil).Twice()
	keys.EXPECT().Rotate(mock.Anything, gw, "alice", (*time.Time)(nil)).Return(key, nil).Once()
	keys.EXPECT().Revoke(mock.Anything, gw, "alice").Return(nil).Once()
	events := make(chanNotifier, 3)
	issuer := appauth.NewPersonalKeyIssuer(keys, nil, nil, func() time.Time { return issuerNow },
		appauth.WithPersonalKeyNotifier(events, tenantGateways{gw: "team-a"}))
	ctx := context.Background()

	_, err := issuer.Create(ctx, gw, "alice", nil)
	require.NoError(t, err)
	created := nextEvent(t, events)
	require.Equal(t, appauth.PersonalKeyCreated, created.Kind)
	require.Equal(t, "team-a", created.TenantID)
	require.Equal(t, key.Auth.ID, created.AuthID)
	require.Equal(t, "alice", created.OwnerID)

	_, err = issuer.Rotate(ctx, gw, "alice")
	require.NoError(t, err)
	rotated := nextEvent(t, events)
	require.Equal(t, appauth.PersonalKeyRotated, rotated.Kind)
	require.False(t, rotated.Renewed)

	require.NoError(t, issuer.Revoke(ctx, gw, "alice"))
	require.Equal(t, appauth.PersonalKeyRevoked, nextEvent(t, events).Kind)
}
