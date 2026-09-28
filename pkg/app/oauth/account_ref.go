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
	"net/url"
	"strings"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/golang-jwt/jwt/v5"
)

const maxAccountRefLen = 320

// resolveAccountRef names the upstream account a connection was made with,
// for the "Signed in as" line: from the ID token when the upstream sent one,
// else from the access token when it is a JWT that carries a readable name,
// else from the upstream's userinfo endpoint — the one its metadata declared,
// or the one known for the providers that do not declare it. Empty when none
// of them says, which the UI shows as a linked account with no name.
func resolveAccountRef(ctx context.Context, userinfo UserInfoClient, cfg *registrydomain.MCPAuth, token *ProviderToken) string {
	if token == nil {
		return ""
	}
	if ref := accountRefFromJWT(token.IDToken); ref != "" {
		return ref
	}
	if ref := readableAccountRefFromJWT(token.AccessToken); ref != "" {
		return ref
	}
	if userinfo == nil || strings.TrimSpace(token.AccessToken) == "" {
		return ""
	}
	endpoint := userinfoURL(cfg)
	if endpoint == "" {
		return ""
	}
	info, err := userinfo.Fetch(ctx, endpoint, token.AccessToken)
	if err != nil {
		return ""
	}
	return accountRefFromClaims(info)
}

func accountRefFromJWT(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return ""
	}
	return accountRefFromClaims(claims)
}

// readableClaims name a person the way they would recognise themselves.
var readableClaims = []string{"email", "emailAddress", "preferred_username", "upn", "unique_name", "login", "name"}

func accountRefFromClaims(claims map[string]any) string {
	if ref := readableAccountRef(claims); ref != "" {
		return ref
	}
	if ref := coerceClaim(claims["sub"]); ref != "" {
		return clipAccountRef(ref)
	}
	return ""
}

func readableAccountRef(claims map[string]any) string {
	for _, key := range readableClaims {
		if ref := coerceClaim(claims[key]); ref != "" {
			return clipAccountRef(ref)
		}
	}
	return ""
}

// readableAccountRefFromJWT reads an access token that happens to be a JWT.
// Access tokens are for the resource, not for us, so only a readable name is
// taken from one: its sub is usually an opaque id nobody would recognise, and
// the userinfo endpoint may still have the email.
func readableAccountRefFromJWT(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Count(raw, ".") != 2 {
		return ""
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return ""
	}
	return readableAccountRef(claims)
}

func userinfoURL(cfg *registrydomain.MCPAuth) string {
	if cfg == nil {
		return ""
	}
	// The endpoint the upstream's own metadata declared, when it declared one
	// over https. It is only ever handed the token that upstream just issued.
	if declared := strings.TrimSpace(cfg.UserinfoURL); declared != "" {
		if u, err := url.Parse(declared); err == nil && u.Scheme == "https" && u.Host != "" {
			return declared
		}
	}
	host := urlHost(cfg.TokenURL)
	if host == "" {
		host = urlHost(cfg.AuthorizeURL)
	}
	host = strings.ToLower(host)
	switch {
	case strings.Contains(host, "googleapis.com"), strings.Contains(host, "accounts.google.com"):
		return "https://openidconnect.googleapis.com/v1/userinfo"
	case strings.Contains(host, "github.com"):
		return "https://api.github.com/user"
	case strings.Contains(host, "login.microsoftonline.com"):
		return "https://graph.microsoft.com/oidc/userinfo"
	default:
		return ""
	}
}

func withIdentityScopes(cfg *registrydomain.MCPAuth) *registrydomain.MCPAuth {
	if cfg == nil {
		return nil
	}
	extra := identityScopesFor(cfg)
	if len(extra) == 0 {
		return cfg
	}
	out := *cfg
	out.Scopes = mergeScopeList(cfg.Scopes, extra)
	return &out
}

func identityScopesFor(cfg *registrydomain.MCPAuth) []string {
	host := strings.ToLower(urlHost(cfg.TokenURL))
	if host == "" {
		host = strings.ToLower(urlHost(cfg.AuthorizeURL))
	}
	switch {
	case strings.Contains(host, "googleapis.com"), strings.Contains(host, "accounts.google.com"):
		return []string{"openid", "email"}
	default:
		return nil
	}
}

func mergeScopeList(existing, extra []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(extra))
	out := make([]string, 0, len(existing)+len(extra))
	for _, scope := range append(append([]string{}, extra...), existing...) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Host
}

func clipAccountRef(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxAccountRefLen {
		return s
	}
	return string(runes[:maxAccountRefLen])
}
