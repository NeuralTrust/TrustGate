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

type MTLSConfig struct {
	CACert              string   `json:"ca_cert"`
	AllowedCommonNames  []string `json:"allowed_common_names,omitempty"`
	AllowedDNSNames     []string `json:"allowed_dns_names,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty"`
}

// ResolveSecretsFrom keeps previously stored secret values when the incoming
// update omits them (empty or the redaction placeholder).
func (c *Config) ResolveSecretsFrom(prev Config) {
	if c.OAuth2 != nil && prev.OAuth2 != nil {
		c.OAuth2.ClientSecret = secret.Resolve(c.OAuth2.ClientSecret, prev.OAuth2.ClientSecret)
	}
}

func (c Config) Validate(t Type) error {
	switch t {
	case TypeAPIKey:
		if c.OAuth2 != nil || c.MTLS != nil {
			return fmt.Errorf("%w: api_key auth does not accept a config payload", ErrInvalidConfig)
		}
		return nil
	case TypeOAuth2:
		if c.OAuth2 == nil || c.MTLS != nil {
			return fmt.Errorf("%w: exactly the oauth2 config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.OAuth2.validate()
	case TypeMTLS:
		if c.MTLS == nil || c.OAuth2 != nil {
			return fmt.Errorf("%w: exactly the mtls config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.MTLS.validate()
	default:
		return fmt.Errorf("%w: %q", ErrInvalidType, t)
	}
}

func (c *OAuth2Config) validate() error {
	if secret.IsMasked(c.ClientSecret) {
		return fmt.Errorf("%w: oauth2.client_secret cannot be a masked value; omit it to keep the stored value", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: oauth2.issuer is required", ErrInvalidConfig)
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
