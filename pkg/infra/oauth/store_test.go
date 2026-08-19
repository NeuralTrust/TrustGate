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
