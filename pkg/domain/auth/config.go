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
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

type Config struct {
	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`
	OIDC   *OIDCConfig   `json:"oidc,omitempty"`
	MTLS   *MTLSConfig   `json:"mtls,omitempty"`
}

type OAuth2Config struct {
	Issuer           string   `json:"issuer"`
	Audiences        []string `json:"audiences,omitempty"`
	JWKSURL          string   `json:"jwks_url,omitempty"`
	IntrospectionURL string   `json:"introspection_url,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	RequiredScopes   []string `json:"required_scopes,omitempty"`
	Algorithms       []string `json:"allowed_algorithms,omitempty"`
}

type OIDCConfig struct {
	Issuer            string   `json:"issuer"`
	Audiences         []string `json:"audiences"`
	JWKSURL           string   `json:"jwks_url,omitempty"`
	PublicKeys        []string `json:"public_keys,omitempty"`
	RequiredScopes    []string `json:"required_scopes,omitempty"`
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	SubjectClaim      string   `json:"subject_claim,omitempty"`
}

type MTLSConfig struct {
	CACert              string   `json:"ca_cert"`
	AllowedCommonNames  []string `json:"allowed_common_names,omitempty"`
	AllowedDNSNames     []string `json:"allowed_dns_names,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty"`
}

func (c *Config) ResolveSecretsFrom(prev Config) {
	if c.OAuth2 != nil && prev.OAuth2 != nil {
		c.OAuth2.ClientSecret = secret.Resolve(c.OAuth2.ClientSecret, prev.OAuth2.ClientSecret)
	}
}

func (c Config) Validate(t Type) error {
	switch t {
	case TypeAPIKey:
		if c.populatedCount() != 0 {
			return fmt.Errorf("%w: api_key auth does not accept a config payload", ErrInvalidConfig)
		}
		return nil
	case TypeOAuth2:
		if c.OAuth2 == nil || c.populatedCount() != 1 {
			return fmt.Errorf("%w: exactly the oauth2 config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.OAuth2.validate()
	case TypeOIDC:
		if c.OIDC == nil || c.populatedCount() != 1 {
			return fmt.Errorf("%w: exactly the oidc config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.OIDC.validate()
	case TypeMTLS:
		if c.MTLS == nil || c.populatedCount() != 1 {
			return fmt.Errorf("%w: exactly the mtls config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.MTLS.validate()
	default:
		return fmt.Errorf("%w: %q", ErrInvalidType, t)
	}
}

func (c Config) populatedCount() int {
	count := 0
	for _, set := range []bool{c.OAuth2 != nil, c.OIDC != nil, c.MTLS != nil} {
		if set {
			count++
		}
	}
	return count
}

func (c *OAuth2Config) validate() error {
	if secret.IsMasked(c.ClientSecret) {
		return fmt.Errorf("%w: oauth2.client_secret cannot be a masked value; omit it to keep the stored value", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: oauth2.issuer is required", ErrInvalidConfig)
	}
	if len(trimmedNonEmpty(c.Audiences)) == 0 {
		return fmt.Errorf("%w: oauth2.audiences is required", ErrInvalidConfig)
	}
	for i, aud := range c.Audiences {
		aud = strings.TrimSpace(aud)
		if aud == "" {
			return fmt.Errorf("%w: oauth2.audiences cannot contain empty entries", ErrInvalidConfig)
		}
		c.Audiences[i] = aud
	}
	for i, scope := range c.RequiredScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return fmt.Errorf("%w: oauth2.required_scopes cannot contain empty entries", ErrInvalidConfig)
		}
		if identity.IsProtocolScope(scope) {
			return fmt.Errorf("%w: oauth2.required_scopes cannot contain the OIDC protocol scope %q (it is not carried by access tokens)",
				ErrInvalidConfig, scope)
		}
		c.RequiredScopes[i] = scope
	}
	if strings.TrimSpace(c.JWKSURL) == "" && strings.TrimSpace(c.IntrospectionURL) == "" {
		// Without an explicit endpoint the JWKS is resolved via OIDC
		// discovery, which needs the issuer to be a resolvable http(s) URL.
		u, err := url.Parse(strings.TrimSpace(c.Issuer))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: oauth2 requires jwks_url or introspection_url, or an http(s) issuer for OIDC discovery", ErrInvalidConfig)
		}
	}
	return nil
}

func (c *OIDCConfig) validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: oidc.issuer is required", ErrInvalidConfig)
	}
	if len(trimmedNonEmpty(c.Audiences)) == 0 {
		return fmt.Errorf("%w: oidc.audiences is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.JWKSURL) == "" && len(trimmedNonEmpty(c.PublicKeys)) == 0 {
		return fmt.Errorf("%w: oidc requires jwks_url or public_keys", ErrInvalidConfig)
	}
	for _, alg := range c.AllowedAlgorithms {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alg)), "HS") {
			return fmt.Errorf("%w: oidc.allowed_algorithms must not include HMAC algorithms", ErrInvalidConfig)
		}
	}
	return nil
}

// ConflictsWith reports whether two oauth2 configs cover the same inbound
// tokens: same issuer and at least one audience in common. An entry without
// audiences accepts any audience of its issuer, so it conflicts with every
// other entry on that issuer. Used as an admin-time guardrail; the request
// path disambiguates at runtime, but duplicate (issuer, audience) pairs make
// token attribution ambiguous everywhere else.
func (c *OAuth2Config) ConflictsWith(other *OAuth2Config) bool {
	if c == nil || other == nil {
		return false
	}
	if strings.TrimSpace(c.Issuer) != strings.TrimSpace(other.Issuer) {
		return false
	}
	if len(c.Audiences) == 0 || len(other.Audiences) == 0 {
		return true
	}
	for _, a := range c.Audiences {
		for _, b := range other.Audiences {
			if normalizeAudience(a) == normalizeAudience(b) {
				return true
			}
		}
	}
	return false
}

// normalizeAudience treats an "api://" resource URI and its bare identifier
// as the same audience (Entra v1 vs v2 aud claim forms).
func normalizeAudience(aud string) string {
	return strings.TrimPrefix(strings.TrimSpace(aud), "api://")
}

func (c MTLSConfig) validate() error {
	if strings.TrimSpace(c.CACert) == "" {
		return fmt.Errorf("%w: mtls.ca_cert is required", ErrInvalidConfig)
	}
	return nil
}

func trimmedNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func (c Config) Value() (driver.Value, error) {
	return json.Marshal(c)
}

func (c *Config) Scan(value interface{}) error {
	if value == nil {
		*c = Config{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	if len(bytes) == 0 {
		*c = Config{}
		return nil
	}
	return json.Unmarshal(bytes, c)
}
