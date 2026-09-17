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

package oauth_test

import (
	"context"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newSessionStore(t *testing.T) (*infraoauth.Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return infraoauth.NewStore(rdb), mr
}

func TestStoreSessionRoundTrip(t *testing.T) {
	store, _ := newSessionStore(t)
	ctx := context.Background()

	rec := appoauth.SessionRecord{
		Subject:   "user-42",
		Scopes:    []string{"mcp.access", "openid"},
		GatewayID: "gw-1",
		AuthID:    "auth-1",
		Audiences: []string{"api://gw"},
	}
	if err := store.SaveSession(ctx, "refresh-1", rec); err != nil {
		t.Fatalf("save session: %v", err)
	}

	got, err := store.GetSession(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got == nil {
		t.Fatal("expected a session record")
		return
	}
	if got.Subject != "user-42" || got.GatewayID != "gw-1" || got.AuthID != "auth-1" {
		t.Fatalf("session record mismatch: %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "mcp.access" {
		t.Fatalf("scopes mismatch: %+v", got.Scopes)
	}
	if len(got.Audiences) != 1 || got.Audiences[0] != "api://gw" {
		t.Fatalf("audiences mismatch: %+v", got.Audiences)
	}
}

func TestStoreGetSessionMissingReturnsNil(t *testing.T) {
	store, _ := newSessionStore(t)

	got, err := store.GetSession(context.Background(), "absent")
	if err != nil {
		t.Fatalf("get missing session: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for an absent session, got %+v", got)
	}
}

func TestStoreRetireSessionBoundsLifetimeToGrace(t *testing.T) {
	store, mr := newSessionStore(t)
	ctx := context.Background()

	if err := store.SaveSession(ctx, "refresh-1", appoauth.SessionRecord{Subject: "user-42"}); err != nil {
		t.Fatalf("save session: %v", err)
	}
	if err := store.RetireSession(ctx, "refresh-1", time.Minute); err != nil {
		t.Fatalf("retire session: %v", err)
	}

	// Inside the grace window the retired token still resolves, so a client's
	// concurrent worker or a retry after a lost response can finish rotating.
	got, err := store.GetSession(ctx, "refresh-1")
	if err != nil || got == nil {
		t.Fatalf("retired session must survive the grace window: rec=%v err=%v", got, err)
	}

	// Retiring again with a longer grace must not extend the bound (EXPIRE LT).
	if err := store.RetireSession(ctx, "refresh-1", time.Hour); err != nil {
		t.Fatalf("re-retire session: %v", err)
	}
	mr.FastForward(time.Minute + time.Second)
	gone, err := store.GetSession(ctx, "refresh-1")
	if err != nil {
		t.Fatalf("get after grace: %v", err)
	}
	if gone != nil {
		t.Fatal("retired session must expire once the grace window has passed")
	}
}

func TestStoreSessionRotation(t *testing.T) {
	store, mr := newSessionStore(t)
	ctx := context.Background()

	rec := appoauth.SessionRecord{Subject: "user-42", Scopes: []string{"mcp.access"}}
	if err := store.SaveSession(ctx, "refresh-old", rec); err != nil {
		t.Fatalf("save old: %v", err)
	}

	loaded, err := store.GetSession(ctx, "refresh-old")
	if err != nil || loaded == nil {
		t.Fatalf("rotation must load the old token: %v", err)
	}
	if err := store.SaveSession(ctx, "refresh-new", rec); err != nil {
		t.Fatalf("save new: %v", err)
	}
	if err := store.RetireSession(ctx, "refresh-old", time.Minute); err != nil {
		t.Fatalf("retire old: %v", err)
	}

	mr.FastForward(time.Minute + time.Second)
	old, err := store.GetSession(ctx, "refresh-old")
	if err != nil {
		t.Fatalf("get old: %v", err)
	}
	if old != nil {
		t.Fatal("rotated-out refresh token must be gone after the grace window")
	}
	fresh, err := store.GetSession(ctx, "refresh-new")
	if err != nil || fresh == nil {
		t.Fatalf("rotated-in refresh token must survive: %v", err)
	}
	if fresh.Subject != "user-42" {
		t.Fatalf("preserved record mismatch: %+v", fresh)
	}
}

// The session's lifetime is fixed at login: the stored TTL runs out at
// ExpiresAt, and re-saving a rotated record only ever gets what is left of
// that window, never a fresh one.
func TestStoreSessionTTLIsAbsoluteNotSliding(t *testing.T) {
	store, mr := newSessionStore(t)
	ctx := context.Background()

	loginAt := time.Now()
	rec := appoauth.SessionRecord{
		Subject:   "user-42",
		LoginAt:   loginAt,
		ExpiresAt: loginAt.Add(time.Hour),
	}
	if err := store.SaveSession(ctx, "refresh-1", rec); err != nil {
		t.Fatalf("save session: %v", err)
	}
	first := mr.TTL("oauth:session:refresh-1")
	if first > time.Hour || first < 59*time.Minute {
		t.Fatalf("TTL must end at ExpiresAt (~1h), not the legacy 30d, got %v", first)
	}

	// A rotation later in the session re-saves the record under a new token
	// with the same deadline: 40 minutes left means a 40 minute TTL.
	rotated := rec
	rotated.ExpiresAt = time.Now().Add(40 * time.Minute)
	if err := store.SaveSession(ctx, "refresh-2", rotated); err != nil {
		t.Fatalf("save rotated session: %v", err)
	}
	second := mr.TTL("oauth:session:refresh-2")
	if second > 40*time.Minute || second < 39*time.Minute {
		t.Fatalf("rotated TTL must be the remaining lifetime (~40m), got %v", second)
	}

	got, err := store.GetSession(ctx, "refresh-2")
	if err != nil || got == nil {
		t.Fatalf("get rotated session: rec=%v err=%v", got, err)
	}
	if !got.LoginAt.Equal(loginAt) || !got.ExpiresAt.Equal(rotated.ExpiresAt) {
		t.Fatalf("LoginAt/ExpiresAt must round-trip, got %+v", got)
	}
}

func TestStoreSaveSessionRefusesExpiredRecord(t *testing.T) {
	store, mr := newSessionStore(t)
	err := store.SaveSession(context.Background(), "refresh-1", appoauth.SessionRecord{
		Subject:   "user-42",
		ExpiresAt: time.Now().Add(-time.Second),
	})
	if err == nil {
		t.Fatal("saving a record past its deadline must fail rather than persist it")
	}
	if mr.Exists("oauth:session:refresh-1") {
		t.Fatal("an expired record must not be written")
	}
}

func TestStoreSessionRecordRoundTripsStoreAccess(t *testing.T) {
	store, _ := newSessionStore(t)
	ctx := context.Background()
	rec := appoauth.SessionRecord{Subject: "user-42", StoreAccess: "curated", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.SaveSession(ctx, "refresh-1", rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.GetSession(ctx, "refresh-1")
	if err != nil || got == nil {
		t.Fatalf("get: rec=%v err=%v", got, err)
	}
	if got.StoreAccess != "curated" {
		t.Fatalf("store_access must round-trip, got %+v", got)
	}
}

// The gateway's own authorization code is single-use: the first redemption
// removes it atomically (GETDEL), so a replayed or injected code finds nothing.
func TestStoreTakeCodeIsSingleUse(t *testing.T) {
	store, _ := newSessionStore(t)
	ctx := context.Background()

	if err := store.SaveCode(ctx, "gw-code", appoauth.CodeGrant{ClientID: "agw-1", Subject: "user-42"}); err != nil {
		t.Fatalf("save code: %v", err)
	}
	first, err := store.TakeCode(ctx, "gw-code")
	if err != nil || first == nil || first.Subject != "user-42" {
		t.Fatalf("first take must return the grant: rec=%v err=%v", first, err)
	}
	second, err := store.TakeCode(ctx, "gw-code")
	if err != nil {
		t.Fatalf("second take: %v", err)
	}
	if second != nil {
		t.Fatal("a redeemed code must not be redeemable again")
	}
}

func TestStoreTakePendingIsSingleUse(t *testing.T) {
	store, _ := newSessionStore(t)
	ctx := context.Background()

	if err := store.SavePending(ctx, "gw-state", appoauth.PendingAuthorization{ClientID: "agw-1"}); err != nil {
		t.Fatalf("save pending: %v", err)
	}
	if first, err := store.TakePending(ctx, "gw-state"); err != nil || first == nil {
		t.Fatalf("first take must return the pending authorization: rec=%v err=%v", first, err)
	}
	second, err := store.TakePending(ctx, "gw-state")
	if err != nil {
		t.Fatalf("second take: %v", err)
	}
	if second != nil {
		t.Fatal("a consumed state must not be consumable again")
	}
}

// TestStoreGatewayClientTTLIsSlidingOnRead verifies the thirty-day sliding TTL
// on dynamically registered clients. The RUN-1501 report claimed dynamic client
// registration has no expiry or cleanup; it does, so no garbage collector is
// warranted. An unused registration disappears on its own, and one that is
// still being read stays.
func TestStoreGatewayClientTTLIsSlidingOnRead(t *testing.T) {
	store, mr := newSessionStore(t)
	ctx := context.Background()

	if err := store.SaveGatewayClient(ctx, appoauth.RegisteredGatewayClient{
		ClientID:     "agw-abc",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}); err != nil {
		t.Fatalf("save client: %v", err)
	}

	ttl := mr.TTL("oauth:gwclient:agw-abc")
	if ttl != 30*24*time.Hour {
		t.Fatalf("registration TTL = %v, want 30 days", ttl)
	}

	mr.FastForward(20 * 24 * time.Hour)
	got, err := store.GetGatewayClient(ctx, "agw-abc")
	if err != nil || got == nil {
		t.Fatalf("client must survive 20 days: %v (err %v)", got, err)
	}
	if ttl := mr.TTL("oauth:gwclient:agw-abc"); ttl != 30*24*time.Hour {
		t.Fatalf("TTL after a read = %v, want it refreshed to 30 days", ttl)
	}

	mr.FastForward(31 * 24 * time.Hour)
	gone, err := store.GetGatewayClient(ctx, "agw-abc")
	if err != nil {
		t.Fatalf("get expired client: %v", err)
	}
	if gone != nil {
		t.Fatalf("an untouched registration must expire on its own, got %+v", gone)
	}
}

// TestStoreGatewayClientManagementKeepsTheTTLSensible covers a client that is
// only ever managed, never used to sign anyone in: reading and updating its
// registration through the RFC 7592 endpoints keeps it alive on the same
// thirty-day sliding window, and deleting it withdraws it at once.
func TestStoreGatewayClientManagementKeepsTheTTLSensible(t *testing.T) {
	store, mr := newSessionStore(t)
	ctx := context.Background()
	key := "oauth:gwclient:agw-managed"

	client := appoauth.RegisteredGatewayClient{
		ClientID:              "agw-managed",
		RedirectURIs:          []string{"https://app.example.com/cb"},
		RegistrationTokenHash: "digest",
	}
	if err := store.SaveGatewayClient(ctx, client); err != nil {
		t.Fatalf("save client: %v", err)
	}

	mr.FastForward(25 * 24 * time.Hour)
	client.RedirectURIs = []string{"https://app.example.com/cb2"}
	if err := store.SaveGatewayClient(ctx, client); err != nil {
		t.Fatalf("update client: %v", err)
	}
	if ttl := mr.TTL(key); ttl != 30*24*time.Hour {
		t.Fatalf("TTL after an update = %v, want 30 days", ttl)
	}

	got, err := store.GetGatewayClient(ctx, "agw-managed")
	if err != nil || got == nil {
		t.Fatalf("read updated client: %v (err %v)", got, err)
	}
	if got.RedirectURIs[0] != "https://app.example.com/cb2" || got.RegistrationTokenHash != "digest" {
		t.Fatalf("update must replace metadata and keep the digest, got %+v", got)
	}

	if err := store.DeleteGatewayClient(ctx, "agw-managed"); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	gone, err := store.GetGatewayClient(ctx, "agw-managed")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if gone != nil {
		t.Fatalf("delete must withdraw the registration, got %+v", gone)
	}
	// Deleting an absent registration is not an error: a client retrying a lost
	// DELETE must not see a failure.
	if err := store.DeleteGatewayClient(ctx, "agw-managed"); err != nil {
		t.Fatalf("delete is idempotent: %v", err)
	}
}
