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
	"reflect"
	"testing"

	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
)

func TestOrgFromToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token map[string]any
		want  string
	}{
		{
			name:  "org in access token",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"sub": "u1", "org": "team-a"})},
			want:  "team-a",
		},
		{
			name: "id_token wins over access token",
			token: map[string]any{
				"id_token":     unsignedJWT(t, map[string]any{"org": "team-id"}),
				"access_token": unsignedJWT(t, map[string]any{"org": "team-access"}),
			},
			want: "team-id",
		},
		{
			name:  "blank org is ignored",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"org": "   "})},
			want:  "",
		},
		{
			name:  "opaque token has no org",
			token: map[string]any{"access_token": "gho_opaque"},
			want:  "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := orgFromToken(tt.token); got != tt.want {
				t.Fatalf("orgFromToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGroupsFromToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token map[string]any
		want  []string
	}{
		{
			name:  "array of groups",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"groups": []any{"Eng", "Admins"}})},
			want:  []string{"Eng", "Admins"},
		},
		{
			name:  "space delimited groups string",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"groups": "Eng Admins"})},
			want:  []string{"Eng", "Admins"},
		},
		{
			name:  "blanks dropped",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"groups": []any{"Eng", "", "  "}})},
			want:  []string{"Eng"},
		},
		{
			name:  "no groups",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"sub": "u1"})},
			want:  nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := groupsFromToken(tt.token); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("groupsFromToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

// mintedSessionClaims verifies the minted gateway session token and returns its
// claims.
func mintedSessionClaims(t *testing.T, signer *infrasts.Signer, resp map[string]any) jwt.MapClaims {
	t.Helper()
	access, _ := resp["access_token"].(string)
	if access == "" {
		t.Fatal("expected a minted access_token")
	}
	claims := jwt.MapClaims{}
	pub := signerPublicKey(t, signer)
	if _, err := jwt.ParseWithClaims(access, claims, func(*jwt.Token) (any, error) { return pub, nil }); err != nil {
		t.Fatalf("minted token must verify: %v", err)
	}
	return claims
}

func TestExchangeCodeSessionModeCarriesOrgAndGroups(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()

	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        "auth-1",
		GatewayID:     "gw-1",
		Org:           "team-a",
		Groups:        []string{"Eng", "Admins"},
		Scopes:        []string{"mcp.access"},
		SessionMode:   true,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	claims := mintedSessionClaims(t, signer, resp)
	if claims["org"] != "team-a" {
		t.Fatalf("session token must carry org, got %v", claims["org"])
	}
	gotGroups := stringSliceClaim(claims["groups"])
	if !reflect.DeepEqual(gotGroups, []string{"Eng", "Admins"}) {
		t.Fatalf("session token must carry groups, got %v", claims["groups"])
	}

	rec := store.peekSession(resp["refresh_token"].(string))
	if rec == nil {
		t.Fatal("session record must be persisted")
		return
	}
	if rec.Org != "team-a" || !reflect.DeepEqual(rec.Groups, []string{"Eng", "Admins"}) {
		t.Fatalf("session record must carry org/groups, got %+v", rec)
	}
}

func TestRefreshSessionPreservesOrgAndGroups(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()

	const oldRefresh = "gwrt_old"
	if err := store.SaveSession(ctx, oldRefresh, SessionRecord{
		Subject:   "user-42",
		Scopes:    []string{"mcp.access"},
		GatewayID: "gw-1",
		AuthID:    "auth-1",
		Org:       "team-a",
		Groups:    []string{"Eng"},
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: oldRefresh,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	claims := mintedSessionClaims(t, signer, resp)
	if claims["org"] != "team-a" {
		t.Fatalf("refreshed token must re-stamp org, got %v", claims["org"])
	}
	if got := stringSliceClaim(claims["groups"]); !reflect.DeepEqual(got, []string{"Eng"}) {
		t.Fatalf("refreshed token must re-stamp groups, got %v", claims["groups"])
	}

	rotated := store.peekSession(resp["refresh_token"].(string))
	if rotated == nil {
		t.Fatal("rotated session must be persisted")
		return
	}
	if rotated.Org != "team-a" || !reflect.DeepEqual(rotated.Groups, []string{"Eng"}) {
		t.Fatalf("rotated record must preserve org/groups, got %+v", rotated)
	}
}
