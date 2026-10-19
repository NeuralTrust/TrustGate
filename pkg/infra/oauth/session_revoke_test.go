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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRevokeSubjectSessionsDeletesOnlyTheTarget(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	expires := time.Now().Add(2 * time.Hour).UTC()

	targetA := defaultRevokeSession("gw-1", "org-1", "user-1", expires)
	targetB := targetA
	targetB.Email = "second@example.com"
	otherOrg := defaultRevokeSession("gw-1", "org-2", "user-1", expires)
	otherOrg.Email = "other-org@example.com"
	otherGateway := defaultRevokeSession("gw-2", "org-1", "user-1", expires)
	otherGateway.Email = "other-gw@example.com"
	otherSubject := defaultRevokeSession("gw-1", "org-1", "user-2", expires)
	otherSubject.Email = "other-subject@example.com"
	operator := targetA
	operator.AuthID = "auth-operator"
	operator.Email = "operator@example.com"

	seeds := map[string]appoauth.SessionRecord{
		"gwrt_target-a":   targetA,
		"gwrt_target-b":   targetB,
		"gwrt_other-org":  otherOrg,
		"gwrt_other-gw":   otherGateway,
		"gwrt_other-user": otherSubject,
		"gwrt_other-idp":  operator,
	}
	for token, rec := range seeds {
		if err := store.SaveSession(ctx, token, rec); err != nil {
			t.Fatalf("save %s: %v", token, err)
		}
	}
	if err := mr.Set("oauth:personal-key:session:keep", "personal"); err != nil {
		t.Fatalf("seed personal key: %v", err)
	}
	if err := mr.Set("oauth:gwclient:keep", "client"); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if err := mr.Set("oauth:code:keep", "grant"); err != nil {
		t.Fatalf("seed code: %v", err)
	}
	if n := ownerIndexSize(t, mr, "gw-1", "user-1"); n != 3 {
		t.Fatalf("shared owner index = %d, want target plus the other org", n)
	}
	if n := ownerIndexSize(t, mr, "gw-1", "user-2"); n != 1 {
		t.Fatalf("other subject index = %d, want 1", n)
	}
	if ownerIndexSize(t, mr, "gw-2", "user-1") != 1 {
		t.Fatal("other gateway index missing")
	}

	revoked, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1")
	if err != nil || revoked != 2 {
		t.Fatalf("revoked %d err %v", revoked, err)
	}
	for _, token := range []string{"gwrt_target-a", "gwrt_target-b"} {
		got, err := store.GetSession(ctx, token)
		if err != nil || got != nil {
			t.Fatalf("%s still present: %+v err %v", token, got, err)
		}
	}
	for token, want := range map[string]string{
		"gwrt_other-org":  "other-org@example.com",
		"gwrt_other-gw":   "other-gw@example.com",
		"gwrt_other-user": "other-subject@example.com",
		"gwrt_other-idp":  "operator@example.com",
	} {
		got, err := store.GetSession(ctx, token)
		if err != nil || got == nil || got.Email != want {
			t.Fatalf("%s = %+v err %v", token, got, err)
		}
	}
	if ownerIndexSize(t, mr, "gw-1", "user-1") != 1 {
		t.Fatal("target digests stayed in the owner index, or the other org was removed")
	}
	if ownerIndexSize(t, mr, "gw-1", "user-2") != 1 || ownerIndexSize(t, mr, "gw-2", "user-1") != 1 {
		t.Fatal("another subject's index changed")
	}
	personal, err := mr.Get("oauth:personal-key:session:keep")
	if err != nil || personal != "personal" {
		t.Fatalf("personal key = %q err %v", personal, err)
	}
	client, err := mr.Get("oauth:gwclient:keep")
	if err != nil || client != "client" {
		t.Fatalf("gateway client = %q err %v", client, err)
	}
	code, err := mr.Get("oauth:code:keep")
	if err != nil || code != "grant" {
		t.Fatalf("code grant = %q err %v", code, err)
	}

	again, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1")
	if err != nil || again != 0 {
		t.Fatalf("repeat revoked %d err %v", again, err)
	}
	still, err := store.GetSession(ctx, "gwrt_other-org")
	if err != nil || still == nil || still.Email != "other-org@example.com" {
		t.Fatalf("repeat touched the other org: %+v err %v", still, err)
	}

	none, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "nobody")
	if err != nil || none != 0 {
		t.Fatalf("absent subject revoked %d err %v", none, err)
	}
}

func TestRefreshAfterRevokeIsInvalidGrant(t *testing.T) {
	t.Parallel()
	store, _ := newSessionStore(t)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).UTC()
	if err := store.SaveSession(ctx, "gwrt_target", defaultRevokeSession("gw-1", "org-1", "user-1", expires)); err != nil {
		t.Fatalf("save target: %v", err)
	}
	if err := store.SaveSession(ctx, "gwrt_other", defaultRevokeSession("gw-1", "org-1", "user-2", expires)); err != nil {
		t.Fatalf("save other: %v", err)
	}
	signer, err := infrasts.NewSigner("https://gw.example.com/sts", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	proxy := appoauth.NewAuthProxy(nil, nil, nil, store, nil, signer, nil)

	if _, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_target",
	})
	var oauthErr *appoauth.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_grant" {
		t.Fatalf("refresh after revoke = %v, want invalid_grant", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_other",
	})
	if err != nil {
		t.Fatalf("other subject refresh: %v", err)
	}
	if resp["token_type"] != "Bearer" {
		t.Fatalf("other subject refresh response: %v", resp)
	}
}

// A record written before the owner index existed is invisible to the delete.
// The marker still refuses it, including when LoginAt was never stored.
func TestPreIndexRecordIsRefusedAfterRevoke(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	token := "gwrt_preindex"
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := mr.Set(digestSessionKey(token), string(raw)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if ownerIndexSize(t, mr, "gw-1", "user-1") != 0 {
		t.Fatal("a pre-index record must not be in the owner index")
	}

	revoked, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1")
	if err != nil || revoked != 0 {
		t.Fatalf("revoked %d err %v, want 0", revoked, err)
	}
	ttl := mr.TTL("oauth:sessions-revoked:gw-1:org-1:user-1")
	if ttl <= 29*24*time.Hour || ttl > 30*24*time.Hour {
		t.Fatalf("revocation marker ttl = %v, want 30 days", ttl)
	}

	_, err = newRevokeProxy(t, store).Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: token,
	})
	requireInvalidGrant(t, err)
	if got, err := store.GetSession(ctx, token); err != nil || got != nil {
		t.Fatalf("pre-index record survived refresh: %+v err %v", got, err)
	}
}

// RetireSession drops the owner-index entry while the token is still inside
// the grace window. The marker has to refuse that token too.
func TestGracePeriodTokenIsRefusedAfterRevoke(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	token := "gwrt_grace"
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	rec.LoginAt = time.Now().Add(-time.Minute).UTC()
	if err := store.SaveSession(ctx, token, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.RetireSession(ctx, token, 60*time.Second); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if ownerIndexSize(t, mr, "gw-1", "user-1") != 0 {
		t.Fatal("a retired token must leave the owner index")
	}
	if got, err := store.GetSession(ctx, token); err != nil || got == nil {
		t.Fatalf("grace token must still resolve before revoke: %+v err %v", got, err)
	}

	revoked, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1")
	if err != nil || revoked != 0 {
		t.Fatalf("revoked %d err %v, want 0", revoked, err)
	}
	_, err = newRevokeProxy(t, store).Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: token,
	})
	requireInvalidGrant(t, err)
	if got, err := store.GetSession(ctx, token); err != nil || got != nil {
		t.Fatalf("grace token survived refresh: %+v err %v", got, err)
	}
}

// SaveSession is the point where an in-flight refresh writes the rotated
// record. Revoking there is the race: the new record is saved after the
// marker, and both it and the presented token have to be gone afterwards.
func TestInFlightRefreshRaceLeavesNoLiveRecord(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	token := "gwrt_live"
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	rec.LoginAt = time.Now().Add(-time.Hour).UTC()
	if err := store.SaveSession(ctx, token, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	proxy := newRevokeProxy(t, &revokeDuringSave{Store: store})
	_, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: token,
	})
	requireInvalidGrant(t, err)
	if got, err := store.GetSession(ctx, token); err != nil || got != nil {
		t.Fatalf("presented token survived the race: %+v err %v", got, err)
	}
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "oauth:session:") {
			t.Fatalf("live session key %s", key)
		}
	}
	if !mr.Exists("oauth:sessions-revoked:gw-1:org-1:user-1") {
		t.Fatal("revocation marker missing")
	}
}

// A login newer than the marker keeps its refresh token, and rotating that
// token keeps working. A login at the marker does not. An operator-IdP
// session for the same subject is not covered by the marker.
func TestLoginAfterRevocationKeepsRefreshing(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	if _, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	markerRaw, err := mr.Get("oauth:sessions-revoked:gw-1:org-1:user-1")
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	marker, err := time.Parse(time.RFC3339Nano, markerRaw)
	if err != nil {
		t.Fatalf("marker time: %v", err)
	}
	fresh := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(2*time.Hour).UTC())
	fresh.LoginAt = marker.Add(time.Second)
	if err := store.SaveSession(ctx, "gwrt_fresh", fresh); err != nil {
		t.Fatalf("save fresh: %v", err)
	}
	equal := fresh
	equal.LoginAt = marker
	if err := store.SaveSession(ctx, "gwrt_equal", equal); err != nil {
		t.Fatalf("save equal: %v", err)
	}
	operator := fresh
	operator.AuthID = "auth-operator"
	operator.LoginAt = marker.Add(-time.Hour)
	if err := store.SaveSession(ctx, "gwrt_operator", operator); err != nil {
		t.Fatalf("save operator: %v", err)
	}

	proxy := newRevokeProxy(t, store)
	resp, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_fresh",
	})
	if err != nil {
		t.Fatalf("fresh login refresh: %v", err)
	}
	next, _ := resp["refresh_token"].(string)
	if next == "" || resp["token_type"] != "Bearer" {
		t.Fatalf("fresh login response: %v", resp)
	}
	again, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: next,
	})
	if err != nil || again["token_type"] != "Bearer" {
		t.Fatalf("second refresh: %v resp %v", err, again)
	}

	_, err = proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_equal",
	})
	requireInvalidGrant(t, err)

	op, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_operator",
	})
	if err != nil || op["token_type"] != "Bearer" {
		t.Fatalf("operator session refresh: %v resp %v", err, op)
	}
}

// A marker that cannot be read must not be treated as "not revoked", and must
// not be treated as invalid_grant. The refresh fails and the record stays.
func TestRefreshWhenMarkerIsUnreadableFailsClosed(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	token := "gwrt_target"
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	rec.LoginAt = time.Now().Add(-time.Minute).UTC()
	if err := store.SaveSession(ctx, token, rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := mr.Set("oauth:sessions-revoked:gw-1:org-1:user-1", "not-a-time"); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	_, err := newRevokeProxy(t, store).Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: token,
	})
	var oauthErr *appoauth.OAuthError
	if err == nil || errors.As(err, &oauthErr) {
		t.Fatalf("unreadable marker = %v, want a store error", err)
	}
	got, err := store.GetSession(ctx, token)
	if err != nil || got == nil {
		t.Fatalf("record after failed marker read: %+v err %v", got, err)
	}
}

func TestSubjectRevokedAtRedisError(t *testing.T) {
	t.Parallel()
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 100 * time.Millisecond,
		MaxRetries:  0,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	_, err := infraoauth.NewStore(rdb).SubjectRevokedAt(context.Background(), "gw-1", "org-1", "user-1")
	if err == nil {
		t.Fatal("a failed marker read must be an error, not a missing marker")
	}
}

// A code issued before the revoke must not become a session. Exchange is
// refused, rather than minting a session whose refresh would then fail.
func TestCodeIssuedBeforeRevokeIsRefusedAtExchange(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	issued := time.Now().Add(-time.Minute).UTC()
	if err := store.SaveCode(ctx, "pre-revoke", sessionCode("user-1", issued)); err != nil {
		t.Fatalf("save code: %v", err)
	}
	if _, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	proxy := newRevokeProxy(t, store)
	_, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType:    "authorization_code",
		Code:         "pre-revoke",
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: "client-verifier",
	})
	requireInvalidGrant(t, err)
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "oauth:session:") {
			t.Fatalf("exchange minted a session: %s", key)
		}
	}

	markerRaw, err := mr.Get("oauth:sessions-revoked:gw-1:org-1:user-1")
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	marker, err := time.Parse(time.RFC3339Nano, markerRaw)
	if err != nil {
		t.Fatalf("marker time: %v", err)
	}
	if err := store.SaveCode(ctx, "post-revoke", sessionCode("user-1", marker.Add(time.Second))); err != nil {
		t.Fatalf("save later code: %v", err)
	}
	resp, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType:    "authorization_code",
		Code:         "post-revoke",
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("code issued after the marker must exchange: %v", err)
	}
	refresh, _ := resp["refresh_token"].(string)
	saved, err := store.GetSession(ctx, refresh)
	if err != nil || saved == nil || !saved.LoginAt.Equal(marker.Add(time.Second)) {
		t.Fatalf("session login = %+v err %v, want the code issue time", saved, err)
	}
	again, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: refresh,
	})
	if err != nil || again["token_type"] != "Bearer" {
		t.Fatalf("refresh of a later login: %v resp %v", err, again)
	}
}

func TestRevocationMarkerTTLIsTheLongerSessionLifetime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	longLived, longRedis := newSessionStore(t)
	longLived.SetDefaultIDPSessionMaxAge(90 * 24 * time.Hour)
	if _, err := longLived.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke long: %v", err)
	}
	if ttl := longRedis.TTL(revocationMarkerKey); ttl <= 89*24*time.Hour || ttl > 90*24*time.Hour {
		t.Fatalf("marker ttl with a 90d cap = %v", ttl)
	}

	shorter, shortRedis := newSessionStore(t)
	shorter.SetDefaultIDPSessionMaxAge(time.Hour)
	if _, err := shorter.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke short: %v", err)
	}
	if ttl := shortRedis.TTL(revocationMarkerKey); ttl <= 29*24*time.Hour || ttl > 30*24*time.Hour {
		t.Fatalf("marker ttl with a 1h cap = %v, want the 30d idle lifetime", ttl)
	}
}

const revocationMarkerKey = "oauth:sessions-revoked:gw-1:org-1:user-1"

func sessionCode(subject string, issued time.Time) appoauth.CodeGrant {
	sum := sha256.Sum256([]byte("client-verifier"))
	return appoauth.CodeGrant{
		RedirectURI:   "https://app.example/cb",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Subject:       subject,
		AuthID:        appauth.DefaultIdPAuthID().String(),
		GatewayID:     "gw-1",
		Org:           "org-1",
		Scopes:        []string{"mcp.access"},
		SessionMode:   true,
		IssuedAt:      issued,
	}
}

type revokeDuringSave struct {
	*infraoauth.Store
	fired bool
}

func (r *revokeDuringSave) SaveSession(ctx context.Context, token string, rec appoauth.SessionRecord) error {
	if !r.fired {
		r.fired = true
		if _, err := r.RevokeSubjectSessions(ctx, rec.Org, rec.GatewayID, rec.Subject); err != nil {
			return err
		}
	}
	return r.Store.SaveSession(ctx, token, rec)
}

func newRevokeProxy(t *testing.T, store appoauth.FlowStore) appoauth.AuthProxy {
	t.Helper()
	return newRevokeProxyWith(t, store)
}

type snapshotMarkers map[string]time.Time

func (m snapshotMarkers) RevokedAt(gatewayID, org, subject string) (time.Time, bool) {
	at, ok := m[gatewayID+"\n"+org+"\n"+subject]
	return at, ok
}

func newRevokeProxyWith(t *testing.T, store appoauth.FlowStore, opts ...appoauth.ProxyOption) appoauth.AuthProxy {
	t.Helper()
	signer, err := infrasts.NewSigner("https://gw.example.com/sts", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return appoauth.NewAuthProxy(nil, nil, nil, store, nil, signer, nil, opts...)
}

// A data plane that does not share the control plane's Redis has no Redis
// marker. The snapshot marker is what refuses the refresh and the exchange,
// and the local session is deleted.
func TestSnapshotMarkerRefusesRefreshAndExchange(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	loginAt := time.Now().Add(-time.Hour).UTC()
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	rec.LoginAt = loginAt
	if err := store.SaveSession(ctx, "gwrt_target", rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	marker := loginAt.Add(time.Minute)
	proxy := newRevokeProxyWith(t, store, appoauth.WithSnapshotRevocations(snapshotMarkers{
		"gw-1\norg-1\nuser-1": marker,
	}))

	_, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_target",
	})
	requireInvalidGrant(t, err)
	if got, err := store.GetSession(ctx, "gwrt_target"); err != nil || got != nil {
		t.Fatalf("revoked session = %+v err %v, want it deleted", got, err)
	}

	if err := store.SaveCode(ctx, "pre-revoke", sessionCode("user-1", loginAt)); err != nil {
		t.Fatalf("save code: %v", err)
	}
	_, err = proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "authorization_code", Code: "pre-revoke",
		RedirectURI: "https://app.example/cb", CodeVerifier: "client-verifier",
	})
	requireInvalidGrant(t, err)
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "oauth:session:") {
			t.Fatalf("exchange minted a session: %s", key)
		}
	}

	if err := store.SaveCode(ctx, "post-revoke", sessionCode("user-1", marker.Add(time.Second))); err != nil {
		t.Fatalf("save later code: %v", err)
	}
	if _, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "authorization_code", Code: "post-revoke",
		RedirectURI: "https://app.example/cb", CodeVerifier: "client-verifier",
	}); err != nil {
		t.Fatalf("code issued after the snapshot marker must exchange: %v", err)
	}
}

// The hosted plane shares Redis with the control plane. A snapshot that has
// no marker leaves that Redis check as the one that refuses the refresh.
func TestHostedRefreshStillUsesTheRedisMarker(t *testing.T) {
	t.Parallel()
	store, _ := newSessionStore(t)
	ctx := context.Background()
	loginAt := time.Now().Add(-time.Hour).UTC()
	rec := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	rec.LoginAt = loginAt
	if err := store.SaveSession(ctx, "gwrt_target", rec); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.RevokeSubjectSessions(ctx, "org-1", "gw-1", "user-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	proxy := newRevokeProxyWith(t, store, appoauth.WithSnapshotRevocations(snapshotMarkers{}))
	_, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_target",
	})
	requireInvalidGrant(t, err)
}

// When both markers exist, the later instant is the one the login is compared
// to. A login between them is refused. A login after both is not.
func TestLaterRevocationMarkerWins(t *testing.T) {
	t.Parallel()
	store, mr := newSessionStore(t)
	ctx := context.Background()
	redisAt := time.Now().Add(-2 * time.Hour).UTC()
	snapshotAt := redisAt.Add(time.Hour)
	if err := mr.Set(revocationMarkerKey, redisAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("redis marker: %v", err)
	}
	proxy := newRevokeProxyWith(t, store, appoauth.WithSnapshotRevocations(snapshotMarkers{
		"gw-1\norg-1\nuser-1": snapshotAt,
	}))

	between := defaultRevokeSession("gw-1", "org-1", "user-1", time.Now().Add(time.Hour).UTC())
	between.LoginAt = redisAt.Add(30 * time.Minute)
	if err := store.SaveSession(ctx, "gwrt_between", between); err != nil {
		t.Fatalf("save between: %v", err)
	}
	_, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_between",
	})
	requireInvalidGrant(t, err)

	after := between
	after.LoginAt = snapshotAt.Add(time.Second)
	if err := store.SaveSession(ctx, "gwrt_after", after); err != nil {
		t.Fatalf("save after: %v", err)
	}
	if _, err := proxy.Exchange(ctx, "http://gw.example.com", appoauth.TokenRequest{
		GrantType: "refresh_token", RefreshToken: "gwrt_after",
	}); err != nil {
		t.Fatalf("login after both markers must refresh: %v", err)
	}
}

func requireInvalidGrant(t *testing.T, err error) {
	t.Helper()
	var oauthErr *appoauth.OAuthError
	if !errors.As(err, &oauthErr) || oauthErr.Code != "invalid_grant" {
		t.Fatalf("got %v, want invalid_grant", err)
	}
}

func defaultRevokeSession(gateway, org, subject string, expires time.Time) appoauth.SessionRecord {
	return appoauth.SessionRecord{
		Subject:   subject,
		GatewayID: gateway,
		Org:       org,
		AuthID:    appauth.DefaultIdPAuthID().String(),
		ExpiresAt: expires,
		Scopes:    []string{"mcp.access"},
	}
}

func ownerIndexSize(t *testing.T, mr *miniredis.Miniredis, gateway, subject string) int {
	t.Helper()
	members, err := mr.SMembers("oauth:session-by-owner:" + gateway + ":" + subject)
	if err != nil {
		return 0
	}
	return len(members)
}
