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

package auth

import (
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// defaultIdPAuthIDString is the stable, well-known AuthID of the built-in
// NeuralTrust identity provider. It is a fixed sentinel (not persisted in the
// database) so that session tokens the gateway mints against the default IdP
// can reference it by `authid`, and so validation/selection code can recognise
// the synthetic auth record regardless of which replica handled the login.
const defaultIdPAuthIDString = "de1de1de-de1d-4de1-8de1-de1de1de1de1"

// DefaultIdPName is the display name carried by the synthetic default auth.
const DefaultIdPName = "NeuralTrust (built-in)"

// DefaultIdPConfig is the environment-sourced configuration of the built-in
// NeuralTrust identity provider. When Issuer is empty the feature is disabled
// and TrustGate behaves exactly as before (an MCP consumer without its own
// oauth2 identity provider cannot broker interactive logins).
type DefaultIdPConfig struct {
	Issuer       string
	AuthorizeURL string
	TokenURL     string
	JWKSURL      string
	ClientID     string
	ClientSecret string
	Audiences    []string
	Scopes       []string
}

// DefaultIdPAuthID returns the well-known AuthID of the built-in NeuralTrust
// identity provider.
func DefaultIdPAuthID() ids.AuthID {
	id, _ := ids.Parse[ids.AuthKind](defaultIdPAuthIDString)
	return id
}

// IsDefaultIdP reports whether the given auth is the synthetic built-in
// NeuralTrust identity provider.
func IsDefaultIdP(a *domain.Auth) bool {
	return a != nil && a.ID == DefaultIdPAuthID()
}

// BuildDefaultIdP turns the environment configuration into a synthetic oauth2
// auth record, or returns nil when the feature is not configured. The record
// is built as a struct literal (bypassing domain.NewAuth) because it is a
// platform-wide fallback with no owning gateway: its GatewayID is resolved per
// request from the addressed MCP consumer, not stored here.
//
// Endpoints default to the conventional paths under the issuer when not set
// explicitly, so operators only have to provide the issuer plus client
// credentials. session_mode is always on: the gateway brokers the login and
// mints its own short-lived MCP session token bound to the platform user.
func BuildDefaultIdP(cfg DefaultIdPConfig) *domain.Auth {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if issuer == "" {
		return nil
	}
	authorize := strings.TrimSpace(cfg.AuthorizeURL)
	if authorize == "" {
		authorize = issuer + "/authorize"
	}
	token := strings.TrimSpace(cfg.TokenURL)
	if token == "" {
		token = issuer + "/token"
	}
	jwks := strings.TrimSpace(cfg.JWKSURL)
	if jwks == "" {
		jwks = issuer + "/jwks"
	}
	audiences := trimmed(cfg.Audiences)
	if len(audiences) == 0 {
		audiences = []string{"neuraltrust-mcp"}
	}
	return &domain.Auth{
		ID:      DefaultIdPAuthID(),
		Name:    DefaultIdPName,
		Type:    domain.TypeOAuth2,
		Enabled: true,
		Config: domain.Config{
			OAuth2: &domain.OAuth2Config{
				Issuer:         issuer,
				Audiences:      audiences,
				JWKSURL:        jwks,
				ClientID:       strings.TrimSpace(cfg.ClientID),
				ClientSecret:   cfg.ClientSecret,
				RequiredScopes: trimmed(cfg.Scopes),
				SessionMode:    true,
				AuthorizeURL:   authorize,
				TokenURL:       token,
			},
		},
	}
}

func trimmed(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
