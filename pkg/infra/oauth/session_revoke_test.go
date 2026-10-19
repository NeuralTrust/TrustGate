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
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/alicebob/miniredis/v2"
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
