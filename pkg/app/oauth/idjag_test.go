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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type stubOIDCVerifier struct {
	hints       appauth.TokenHints
	peekErr     error
	verified    *appauth.VerifiedClaims
	verifyErr   error
	lastCfg     authdomain.OIDCConfig
	verifyCalls int
}

func (s *stubOIDCVerifier) Peek(string) (appauth.TokenHints, error) {
	if s.peekErr != nil {
		return appauth.TokenHints{}, s.peekErr
	}
	return s.hints, nil
}

func (s *stubOIDCVerifier) Verify(_ context.Context, _ string, cfg authdomain.OIDCConfig) (*appauth.VerifiedClaims, error) {
	s.verifyCalls++
	s.lastCfg = cfg
	if s.verifyErr != nil {
		return nil, s.verifyErr
	}
	return s.verified, nil
}

func jagJWT(typ, alg string) string {
	header, _ := json.Marshal(map[string]string{"typ": typ, "alg": alg})
	payload, _ := json.Marshal(map[string]any{"sub": "x"})
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc(header) + "." + enc(payload) + ".sig"
}

func validJAGClaims(now time.Time, extra map[string]any) map[string]any {
	c := map[string]any{
		"sub":       "user-1",
		"iss":       "https://idp.example.com",
		"aud":       "https://gw.example.com",
		"resource":  "https://gw.example.com/v1/mcp/dev",
		"client_id": "agw-client",
		"jti":       "jti-1",
		"iat":       float64(now.Unix()),
		"exp":       float64(now.Add(time.Hour).Unix()),
		"email":     "nobody@example.com",
	}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func emaAuth(t *testing.T, cfg authdomain.OAuth2Config) *authdomain.Auth {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = "https://idp.example.com"
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = "https://idp.example.com/jwks"
	}
	if cfg.RequiredScopes == nil {
		cfg.RequiredScopes = []string{"mcp.access"}
	}
	return &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Type:      authdomain.TypeOAuth2,
		Enabled:   true,
		Config:    authdomain.Config{OAuth2: &cfg},
	}
}

func TestValidateIDJAG(t *testing.T) {
	t.Parallel()
	now := time.Now()
	baseURL := "https://gw.example.com"
	resource := "https://gw.example.com/v1/mcp/dev"
	goodClaims := validJAGClaims(now, nil)
	goodHints := appauth.TokenHints{Issuer: "https://idp.example.com", Algorithm: "RS256"}

	tests := []struct {
		name      string
		typ       string
		alg       string
		hints     appauth.TokenHints
		peekErr   error
		claims    map[string]any
		scopes    []string
		verifyErr error
		jwks      string
		subject   string
		req       TokenRequest
		wantCode  string
		wantAud   string
	}{
		{
			name:    "valid",
			typ:     idJAGTyp,
			alg:     "RS256",
			hints:   goodHints,
			claims:  goodClaims,
			scopes:  []string{"mcp.access", "openid"},
			req:     TokenRequest{ClientID: "agw-client", Resource: resource},
			wantAud: baseURL,
		},
		{
			name:     "wrong typ",
			typ:      "JWT",
			alg:      "RS256",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "hmac",
			typ:      idJAGTyp,
			alg:      "HS256",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "none alg",
			typ:      idJAGTyp,
			alg:      "none",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "iss mismatch",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    appauth.TokenHints{Issuer: "https://other.example.com", Algorithm: "RS256"},
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:      "aud rejected by verifier",
			typ:       idJAGTyp,
			alg:       "RS256",
			hints:     goodHints,
			claims:    goodClaims,
			scopes:    []string{"mcp.access"},
			verifyErr: errors.New("audience"),
			req:       TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode:  "invalid_grant",
			wantAud:   baseURL,
		},
		{
			name:     "resource mismatch",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"resource": "https://other.example.com/mcp"}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "scope extra",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access", "admin"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "missing iat",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"iat": nil}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "expired",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"exp": float64(now.Add(-time.Minute).Unix())}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "future nbf",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"nbf": float64(now.Add(time.Hour).Unix())}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "missing jti",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"jti": nil}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "oid is not silent subject",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   validJAGClaims(now, map[string]any{"sub": nil, "oid": "entra-oid"}),
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:    "act ignored on accept",
			typ:     idJAGTyp,
			alg:     "RS256",
			hints:   goodHints,
			claims:  validJAGClaims(now, map[string]any{"act": map[string]any{"sub": "actor"}}),
			scopes:  []string{"mcp.access"},
			req:     TokenRequest{ClientID: "agw-client", Resource: resource},
			wantAud: baseURL,
		},
		{
			name:      "jwks refresh deny",
			typ:       idJAGTyp,
			alg:       "RS256",
			hints:     goodHints,
			claims:    goodClaims,
			scopes:    []string{"mcp.access"},
			verifyErr: errors.New("jwks refresh failed"),
			req:       TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode:  "invalid_grant",
		},
		{
			name:     "http jwks denied",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			jwks:     "http://idp.example.com/jwks",
			req:      TokenRequest{ClientID: "agw-client", Resource: resource},
			wantCode: "invalid_grant",
		},
		{
			name:     "client_id mismatch",
			typ:      idJAGTyp,
			alg:      "RS256",
			hints:    goodHints,
			claims:   goodClaims,
			scopes:   []string{"mcp.access"},
			req:      TokenRequest{ClientID: "other-client", Resource: resource},
			wantCode: "invalid_grant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := &stubOIDCVerifier{
				hints:     tc.hints,
				peekErr:   tc.peekErr,
				verifyErr: tc.verifyErr,
			}
			if tc.claims != nil {
				stub.verified = &appauth.VerifiedClaims{Subject: "user-1", Claims: tc.claims, Scopes: tc.scopes}
			}
			cfg := authdomain.OAuth2Config{}
			if tc.jwks != "" {
				cfg.JWKSURL = tc.jwks
			}
			auth := emaAuth(t, cfg)
			p := &authProxy{verifier: stub}
			req := tc.req
			req.Assertion = jagJWT(tc.typ, tc.alg)
			got, err := p.validateIDJAG(context.Background(), baseURL, auth, req)
			if tc.wantCode != "" {
				var oe *OAuthError
				if !errors.As(err, &oe) || oe.Code != tc.wantCode {
					t.Fatalf("error = %v, want %s", err, tc.wantCode)
				}
				if got != nil {
					t.Fatal("expected no result on deny")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.subject != "user-1" {
				t.Fatalf("subject = %q", got.subject)
			}
			if tc.wantAud != "" {
				if len(stub.lastCfg.Audiences) != 1 || stub.lastCfg.Audiences[0] != tc.wantAud {
					t.Fatalf("verify aud = %v, want [%s]", stub.lastCfg.Audiences, tc.wantAud)
				}
				if stub.lastCfg.JWKSURL != auth.Config.OAuth2.JWKSURL {
					t.Fatalf("verify jwks = %q, want configured %q", stub.lastCfg.JWKSURL, auth.Config.OAuth2.JWKSURL)
				}
			}
		})
	}
}

func TestEMALogsOmitSecrets(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	now := time.Now()
	claims := validJAGClaims(now, map[string]any{"email": "secret.user@example.com"})
	stub := &stubOIDCVerifier{
		hints:    appauth.TokenHints{Issuer: "https://idp.example.com", Algorithm: "RS256"},
		verified: &appauth.VerifiedClaims{Subject: "user-1", Claims: claims, Scopes: []string{"mcp.access"}},
	}
	auth := emaAuth(t, authdomain.OAuth2Config{})
	p := &authProxy{verifier: stub}
	req := TokenRequest{
		Assertion: jagJWT(idJAGTyp, "RS256"),
		ClientID:  "agw-client",
		Resource:  "https://gw.example.com/v1/mcp/dev",
		GrantType: grantJWTBearer,
	}
	if _, err := p.validateIDJAG(context.Background(), "https://gw.example.com", auth, req); err != nil {
		t.Fatalf("accept: %v", err)
	}
	req.Assertion = jagJWT("JWT", "RS256")
	if _, err := p.validateIDJAG(context.Background(), "https://gw.example.com", auth, req); err == nil {
		t.Fatal("expected deny")
	}
	logs := buf.String()
	forbidden := []string{
		grantJWTBearer,
		"secret.user@example.com",
		"nobody@example.com",
	}
	for _, s := range forbidden {
		if s != "" && strings.Contains(logs, s) {
			t.Fatalf("log leaked %q: %s", s, logs)
		}
	}
	if !strings.Contains(logs, "oauth.ema.accept") || !strings.Contains(logs, "oauth.ema.deny") {
		t.Fatalf("expected accept and deny events, got %s", logs)
	}
}
