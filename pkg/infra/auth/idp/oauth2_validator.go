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

package idp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

// OAuth2TokenValidator adapts the shared IDP verifier to the MCP-plane
// JWTValidator port: it resolves key material via OIDC discovery when the
// config has no explicit JWKS URL and yields an identity.Principal carrying
// the raw token for downstream exchange/passthrough.
type OAuth2TokenValidator struct {
	verifier  appauth.IDPVerifier
	discovery *discovery
}

var _ appauth.JWTValidator = (*OAuth2TokenValidator)(nil)

func NewOAuth2TokenValidator(verifier appauth.IDPVerifier, client *http.Client) *OAuth2TokenValidator {
	return &OAuth2TokenValidator{verifier: verifier, discovery: newDiscovery(client)}
}

func (v *OAuth2TokenValidator) Validate(ctx context.Context, raw string, cfg *domain.OAuth2Config) (*identity.Principal, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: no oauth2 config", ErrInvalidToken)
	}
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	if jwksURL == "" {
		discovered, err := v.discovery.jwksURI(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		jwksURL = discovered
	}
	verified, err := v.verifier.Verify(ctx, raw, domain.IDPConfig{
		Issuer:            cfg.Issuer,
		Audiences:         cfg.Audiences,
		JWKSURL:           jwksURL,
		AllowedAlgorithms: cfg.Algorithms,
	})
	if err != nil {
		return nil, err
	}
	principal := &identity.Principal{
		Subject:  subjectOf(verified),
		Method:   identity.MethodJWT,
		Issuer:   cfg.Issuer,
		Claims:   verified.Claims,
		Scopes:   enrichScopes(verified),
		RawToken: raw,
	}
	if !principal.HasScopes(cfg.RequiredScopes) {
		return nil, fmt.Errorf("%w: missing required scopes", ErrMissingRequiredScope)
	}
	return principal, nil
}

// subjectOf prefers the Entra `oid` claim over `sub`: Entra subjects are
// pairwise per app while oid identifies the user across the tenant, which is
// what vault credentials and consent grants are keyed on.
func subjectOf(verified *appauth.VerifiedClaims) string {
	if oid, ok := verified.Claims["oid"].(string); ok && oid != "" {
		return oid
	}
	return verified.Subject
}

// enrichScopes extends the standard scope claims with Auth0-style
// `permissions` and `roles` arrays so RequiredScopes can match either.
func enrichScopes(verified *appauth.VerifiedClaims) []string {
	seen := make(map[string]struct{}, len(verified.Scopes))
	out := make([]string, 0, len(verified.Scopes))
	add := func(scope string) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return
		}
		if _, dup := seen[scope]; dup {
			return
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	for _, scope := range verified.Scopes {
		add(scope)
	}
	for _, claim := range []string{"permissions", "roles"} {
		values, ok := verified.Claims[claim].([]any)
		if !ok {
			continue
		}
		for _, value := range values {
			if scope, ok := value.(string); ok {
				add(scope)
			}
		}
	}
	return out
}
