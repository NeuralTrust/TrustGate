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

package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

func TestMergeDirectoryGroupsUnionsWithTheLoginClaim(t *testing.T) {
	t.Parallel()
	if got := MergeDirectoryGroups([]string{"A", "B"}, []string{"C"}); !sameGroups(got, []string{"A", "B", "C"}) {
		t.Fatalf("claim {A,B} + push {C} = %v", got)
	}
	if got := MergeDirectoryGroups([]string{"A"}, nil); !sameGroups(got, []string{"A"}) {
		t.Fatalf("claim {A} + push [] = %v", got)
	}
	if got := MergeDirectoryGroups([]string{"A"}, []string{}); !sameGroups(got, []string{"A"}) {
		t.Fatalf("claim {A} + empty list = %v", got)
	}
	once := MergeDirectoryGroups([]string{"A", "B"}, []string{"B", "C"})
	twice := MergeDirectoryGroups([]string{"A", "B"}, []string{"C", "B", "C"})
	if !sameGroups(once, []string{"A", "B", "C"}) || !sameGroups(twice, once) {
		t.Fatalf("re-push = %v then %v", once, twice)
	}
}

func TestApplyDirectoryGroupsToRecordLeavesExpiry(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	login := expires.Add(-time.Hour)
	rec := SessionRecord{
		Groups: []string{"A", "B"}, ClaimGroups: []string{"B", "A"}, ClaimSnapshot: true,
		ExpiresAt: expires, LoginAt: login, Email: "ada@example.com",
	}
	ApplyDirectoryGroupsToRecord(&rec, []string{"C"})
	if !rec.ExpiresAt.Equal(expires) || !rec.LoginAt.Equal(login) || rec.Email != "ada@example.com" {
		t.Fatalf("record fields changed: %+v", rec)
	}
	if !rec.ClaimSnapshot || !sameGroups(rec.ClaimGroups, []string{"B", "A"}) {
		t.Fatalf("claim snapshot = %v snapshot %v", rec.ClaimGroups, rec.ClaimSnapshot)
	}
	if !sameGroups(rec.Groups, []string{"A", "B", "C"}) {
		t.Fatalf("groups = %v", rec.Groups)
	}
	ApplyDirectoryGroupsToRecord(&rec, []string{"C"})
	if !sameGroups(rec.Groups, []string{"A", "B", "C"}) || !rec.ExpiresAt.Equal(expires) {
		t.Fatalf("re-push changed the record: %+v", rec)
	}
	ApplyDirectoryGroupsToRecord(&rec, nil)
	if !sameGroups(rec.Groups, []string{"A", "B"}) || !rec.ExpiresAt.Equal(expires) {
		t.Fatalf("empty push stripped the claim or moved the deadline: %+v", rec)
	}
}

func TestExchangeRecordsTheLoginGroupsClaim(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, http.DefaultClient, store, nil, newTestSigner(t), nil)
	ctx := context.Background()
	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		ClientID:      "cursor-client",
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        appauth.DefaultIdPAuthID().String(),
		GatewayID:     "gw-1",
		Org:           "team-a",
		Groups:        []string{"idp-only", "eng"},
		Scopes:        []string{"mcp.access"},
		SessionMode:   true,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}
	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType: "authorization_code", Code: "gw-code",
		RedirectURI: "cursor://anysphere.cursor-mcp/oauth/callback", CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rec := store.peekSession(resp["refresh_token"].(string))
	if rec == nil || !rec.ClaimSnapshot || !sameGroups(rec.ClaimGroups, []string{"idp-only", "eng"}) || !sameGroups(rec.Groups, rec.ClaimGroups) {
		t.Fatalf("login snapshot = %+v", rec)
	}
}

// A directory push is added to the login claim. Names from that claim stay
// when the push omits them, and the refresh record's deadline is unchanged
// when the session has an absolute lifetime.
func TestRefreshUnionsTheDirectoryPushWithTheLoginClaim(t *testing.T) {
	t.Parallel()
	loginAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	expires := loginAt.Add(30 * 24 * time.Hour)
	now := loginAt.Add(time.Hour)

	t.Run("absolute lifetime keeps the deadline", func(t *testing.T) {
		t.Parallel()
		rec := refreshedGroups(t, loginAt, expires, now, 24*time.Hour, []string{"sre"}, time.Time{}, nil)
		if !rec.ExpiresAt.Equal(expires) {
			t.Fatalf("ExpiresAt = %v, want %v", rec.ExpiresAt, expires)
		}
		if !sameGroups(rec.Groups, []string{"eng", "idp-only", "sre"}) {
			t.Fatalf("groups = %v", rec.Groups)
		}
	})

	t.Run("no absolute lifetime still slides one idle window", func(t *testing.T) {
		t.Parallel()
		rec := refreshedGroups(t, loginAt, expires, now, 0, []string{"sre"}, time.Time{}, nil)
		if want := now.Add(sessionIdleLifetime); !rec.ExpiresAt.Equal(want) {
			t.Fatalf("ExpiresAt = %v, want the existing idle slide %v", rec.ExpiresAt, want)
		}
		if !sameGroups(rec.Groups, []string{"eng", "idp-only", "sre"}) {
			t.Fatalf("groups = %v", rec.Groups)
		}
	})

	t.Run("empty push leaves the claim", func(t *testing.T) {
		t.Parallel()
		rec := refreshedGroups(t, loginAt, expires, now, 24*time.Hour, []string{}, time.Time{}, nil)
		if !rec.ExpiresAt.Equal(expires) || !sameGroups(rec.Groups, []string{"eng", "idp-only"}) {
			t.Fatalf("empty push = %+v", rec)
		}
	})
}

func TestRefreshKeepsSnapshotWhenDirectoryLookupFails(t *testing.T) {
	t.Parallel()
	loginAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	expires := loginAt.Add(30 * 24 * time.Hour)
	rec := refreshedGroups(t, loginAt, expires, loginAt.Add(time.Hour), 24*time.Hour, nil, time.Time{}, errDirectoryLookup)
	if !rec.ExpiresAt.Equal(expires) || !sameGroups(rec.Groups, []string{"eng", "idp-only"}) {
		t.Fatalf("failed lookup must leave the record, got %+v", rec)
	}
}

func TestRefreshIgnoresADirectoryPushFromBeforeLogin(t *testing.T) {
	t.Parallel()
	loginAt := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	expires := loginAt.Add(30 * 24 * time.Hour)
	pushedAt := loginAt.Add(-time.Hour)
	rec := refreshedGroups(t, loginAt, expires, loginAt.Add(time.Minute), 24*time.Hour, []string{"sre"}, pushedAt, nil)
	if !sameGroups(rec.Groups, []string{"eng", "idp-only"}) {
		t.Fatalf("groups = %v, want the login snapshot", rec.Groups)
	}
}

type directoryLookupStore struct {
	*memFlowStore
	groups []string
	at     time.Time
	err    error
}

func (s *directoryLookupStore) LookupDirectoryGroups(context.Context, string, string, string) ([]string, time.Time, bool, error) {
	if s.err != nil {
		return nil, time.Time{}, false, s.err
	}
	return s.groups, s.at, true, nil
}

var errDirectoryLookup = errLookup("directory groups unavailable")

type errLookup string

func (e errLookup) Error() string { return string(e) }

func refreshedGroups(t *testing.T, loginAt, expires, now time.Time, maxAge time.Duration, directory []string, pushedAt time.Time, lookupErr error) *SessionRecord {
	t.Helper()
	base := newMemFlowStore()
	store := &directoryLookupStore{memFlowStore: base, groups: directory, at: pushedAt, err: lookupErr}
	opts := []ProxyOption{}
	if maxAge > 0 {
		opts = append(opts, WithDefaultIdPSessionMaxAge(maxAge))
	}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, &http.Client{Transport: failingTransport{t}}, store, nil, newTestSigner(t), nil, opts...).(*authProxy)
	proxy.now = fixedClock(now)
	const refresh = "gwrt_old"
	if err := base.SaveSession(context.Background(), refresh, SessionRecord{
		Subject: "user-1", GatewayID: "gw-1", AuthID: appauth.DefaultIdPAuthID().String(), Org: "org-1",
		Groups: []string{"eng", "idp-only"}, ClaimGroups: []string{"idp-only", "eng"}, ClaimSnapshot: true,
		Scopes: []string{"mcp.access"}, LoginAt: loginAt, ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType: "refresh_token", RefreshToken: refresh,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	access, _ := resp["access_token"].(string)
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(access, claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if directory != nil && pushedAt.IsZero() && lookupErr == nil {
		want := MergeDirectoryGroups([]string{"eng", "idp-only"}, directory)
		if got := identity.GroupsFromClaims(map[string]any(claims)); !sameGroups(got, want) {
			t.Fatalf("access token groups = %v, want %v", got, want)
		}
	}
	rec := base.peekSession(resp["refresh_token"].(string))
	if rec == nil {
		t.Fatal("refresh must persist a record")
	}
	return rec
}

func sameGroups(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
