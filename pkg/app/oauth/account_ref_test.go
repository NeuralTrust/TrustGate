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

// recordingUserInfo answers like userInfoMap and says which endpoint it was
// asked, so a test can tell the declared endpoint from a guessed one.
type recordingUserInfo struct {
	claims   map[string]any
	endpoint *string
}

func (r recordingUserInfo) Fetch(_ context.Context, endpoint, _ string) (map[string]any, error) {
	*r.endpoint = endpoint
	return r.claims, nil
}

// Calendly's MCP sends no ID token and is none of the providers the gateway
// knows a userinfo endpoint for: the one its metadata declares is asked.
func TestAccountRefFromTheDeclaredUserinfoEndpoint(t *testing.T) {
	t.Parallel()
	var asked string
	cfg := &registrydomain.MCPAuth{
		TokenURL:    "https://auth.calendly.com/oauth/token",
		UserinfoURL: "https://auth.calendly.com/userinfo",
	}
	got := resolveAccountRef(context.Background(), recordingUserInfo{claims: map[string]any{"email": "ada@example.com"}, endpoint: &asked}, cfg, &ProviderToken{AccessToken: "opaque"})
	if got != "ada@example.com" {
		t.Fatalf("account ref = %q, want the email userinfo gave", got)
	}
	if asked != "https://auth.calendly.com/userinfo" {
		t.Fatalf("asked %q, want the declared endpoint", asked)
	}
}

func TestUserinfoURLIgnoresADeclaredEndpointThatIsNotHTTPS(t *testing.T) {
	t.Parallel()
	for _, declared := range []string{"http://auth.example.com/userinfo", "not a url", "file:///etc/passwd"} {
		cfg := &registrydomain.MCPAuth{TokenURL: "https://auth.example.com/token", UserinfoURL: declared}
		if got := userinfoURL(cfg); got != "" {
			t.Fatalf("userinfoURL(%q) = %q, want empty", declared, got)
		}
	}
}

func TestAccountRefFromAReadableAccessToken(t *testing.T) {
	t.Parallel()
	token := &ProviderToken{AccessToken: mustSignedJWT(t, jwt.MapClaims{"preferred_username": "ada", "sub": "u_8f2a"})}
	if got := resolveAccountRef(context.Background(), nil, nil, token); got != "ada" {
		t.Fatalf("account ref = %q, want the readable name from the access token", got)
	}
}

// An access token's sub is an id nobody would recognise, so it is not shown;
// userinfo is asked instead.
func TestAccountRefSkipsAnAccessTokenThatOnlyHasASub(t *testing.T) {
	t.Parallel()
	var asked string
	cfg := &registrydomain.MCPAuth{TokenURL: "https://auth.example.com/token", UserinfoURL: "https://auth.example.com/userinfo"}
	token := &ProviderToken{AccessToken: mustSignedJWT(t, jwt.MapClaims{"sub": "u_8f2a"})}
	got := resolveAccountRef(context.Background(), recordingUserInfo{claims: map[string]any{"email": "ada@example.com"}, endpoint: &asked}, cfg, token)
	if got != "ada@example.com" {
		t.Fatalf("account ref = %q, want userinfo's email over the access token's sub", got)
	}
}

func TestAutoAuthCarriesTheDeclaredUserinfoEndpoint(t *testing.T) {
	t.Parallel()
	meta := &UpstreamAuthServer{AuthorizationEndpoint: "https://a/authorize", TokenEndpoint: "https://a/token", UserinfoEndpoint: "https://a/userinfo"}
	got := autoAuth(&registrydomain.MCPAuth{}, meta, &RegisteredClient{ClientID: "c"})
	if got.UserinfoURL != "https://a/userinfo" {
		t.Fatalf("UserinfoURL = %q", got.UserinfoURL)
	}
	if manualAuth(&registrydomain.MCPAuth{}, meta).UserinfoURL != "https://a/userinfo" {
		t.Fatal("manual registration must carry it too")
	}
}
