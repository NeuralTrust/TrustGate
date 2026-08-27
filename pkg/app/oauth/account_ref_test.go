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
	"errors"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/golang-jwt/jwt/v5"
)

func TestAccountRefFromIDTokenPrefersEmail(t *testing.T) {
	t.Parallel()
	token := &ProviderToken{IDToken: mustSignedJWT(t, jwt.MapClaims{
		"email": "victor@neuraltrust.ai",
		"sub":   "108234",
	})}
	got := resolveAccountRef(context.Background(), nil, nil, token)
	if got != "victor@neuraltrust.ai" {
		t.Fatalf("account ref = %q, want email", got)
	}
}

func TestAccountRefFromUserInfoWhenNoIDToken(t *testing.T) {
	t.Parallel()
	cfg := &registrydomain.MCPAuth{
		TokenURL: "https://oauth2.googleapis.com/token",
	}
	client := userInfoMap{"email": "ada@example.com", "sub": "1"}
	got := resolveAccountRef(context.Background(), client, cfg, &ProviderToken{AccessToken: "ya29.tok"})
	if got != "ada@example.com" {
		t.Fatalf("account ref = %q", got)
	}
}

func TestAccountRefUserInfoFailureIsIgnored(t *testing.T) {
	t.Parallel()
	cfg := &registrydomain.MCPAuth{TokenURL: "https://github.com/login/oauth/access_token"}
	got := resolveAccountRef(context.Background(), failingUserInfo{}, cfg, &ProviderToken{AccessToken: "gho_x"})
	if got != "" {
		t.Fatalf("account ref = %q, want empty when userinfo fails", got)
	}
}

func TestWithIdentityScopesAddsGoogleOpenID(t *testing.T) {
	t.Parallel()
	cfg := &registrydomain.MCPAuth{
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		Scopes:       []string{"https://www.googleapis.com/auth/gmail.readonly"},
	}
	got := withIdentityScopes(cfg)
	if len(got.Scopes) < 3 || got.Scopes[0] != "openid" || got.Scopes[1] != "email" {
		t.Fatalf("scopes = %v, want openid and email first", got.Scopes)
	}
	if withIdentityScopes(cfg) == cfg {
		t.Fatal("must copy the auth config so stored registry scopes stay unchanged")
	}
}

func TestUserinfoURLKnownHosts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		tokenURL string
		want     string
	}{
		{"https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo"},
		{"https://github.com/login/oauth/access_token", "https://api.github.com/user"},
		{"https://login.microsoftonline.com/ten/oauth2/v2.0/token", "https://graph.microsoft.com/oidc/userinfo"},
		{"https://mcp.linear.app/token", ""},
	}
	for _, tt := range tests {
		if got := userinfoURL(&registrydomain.MCPAuth{TokenURL: tt.tokenURL}); got != tt.want {
			t.Fatalf("userinfoURL(%q) = %q, want %q", tt.tokenURL, got, tt.want)
		}
	}
}

func mustSignedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return raw
}

type userInfoMap map[string]any

func (u userInfoMap) Fetch(context.Context, string, string) (map[string]any, error) {
	return map[string]any(u), nil
}

type failingUserInfo struct{}

func (failingUserInfo) Fetch(context.Context, string, string) (map[string]any, error) {
	return nil, errors.New("userinfo down")
}
