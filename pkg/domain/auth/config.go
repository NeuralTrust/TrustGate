package auth

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
)

type Config struct {
	OAuth2       *OAuth2Config       `json:"oauth2,omitempty"`
	OAuth2Client *OAuth2ClientConfig `json:"oauth2_client,omitempty"`
	IDP          *IDPConfig          `json:"idp,omitempty"`
	MTLS         *MTLSConfig         `json:"mtls,omitempty"`
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

type OAuth2ClientConfig struct {
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"`
	Audience     string   `json:"audience,omitempty"`
}

type IDPConfig struct {
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
	if c.OAuth2Client != nil && prev.OAuth2Client != nil {
		c.OAuth2Client.ClientSecret = secret.Resolve(c.OAuth2Client.ClientSecret, prev.OAuth2Client.ClientSecret)
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
	case TypeOAuth2Client:
		if c.OAuth2Client == nil || c.populatedCount() != 1 {
			return fmt.Errorf("%w: exactly the oauth2_client config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.OAuth2Client.validate()
	case TypeIDP:
		if c.IDP == nil || c.populatedCount() != 1 {
			return fmt.Errorf("%w: exactly the idp config payload must be set for type %q", ErrInvalidConfig, t)
		}
		return c.IDP.validate()
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
	for _, set := range []bool{c.OAuth2 != nil, c.OAuth2Client != nil, c.IDP != nil, c.MTLS != nil} {
		if set {
			count++
		}
	}
	return count
}

func (c OAuth2Config) validate() error {
	if secret.IsMasked(c.ClientSecret) {
		return fmt.Errorf("%w: oauth2.client_secret cannot be a masked value; omit it to keep the stored value", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: oauth2.issuer is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.JWKSURL) == "" {
		return fmt.Errorf("%w: oauth2.jwks_url is required; introspection_url is not supported for proxy auth", ErrInvalidConfig)
	}
	if len(trimmedNonEmpty(c.Audiences)) == 0 {
		return fmt.Errorf("%w: oauth2.audiences is required", ErrInvalidConfig)
	}
	return nil
}

func (c OAuth2ClientConfig) validate() error {
	if secret.IsMasked(c.ClientSecret) {
		return fmt.Errorf("%w: oauth2_client.client_secret cannot be a masked value; omit it to keep the stored value", ErrInvalidConfig)
	}
	tokenURL := strings.TrimSpace(c.TokenURL)
	if tokenURL == "" {
		return fmt.Errorf("%w: oauth2_client.token_url is required", ErrInvalidConfig)
	}
	parsed, err := url.Parse(tokenURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%w: oauth2_client.token_url must be a valid https URL", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("%w: oauth2_client.client_id is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return fmt.Errorf("%w: oauth2_client.client_secret is required", ErrInvalidConfig)
	}
	return nil
}

func (c IDPConfig) validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: idp.issuer is required", ErrInvalidConfig)
	}
	if len(trimmedNonEmpty(c.Audiences)) == 0 {
		return fmt.Errorf("%w: idp.audiences is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.JWKSURL) == "" && len(trimmedNonEmpty(c.PublicKeys)) == 0 {
		return fmt.Errorf("%w: idp requires jwks_url or public_keys", ErrInvalidConfig)
	}
	for _, alg := range c.AllowedAlgorithms {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alg)), "HS") {
			return fmt.Errorf("%w: idp.allowed_algorithms must not include HMAC algorithms", ErrInvalidConfig)
		}
	}
	return nil
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
