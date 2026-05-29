package auth

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

type Config struct {
	APIKey *APIKeyConfig `json:"api_key,omitempty"`
	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`
	MTLS   *MTLSConfig   `json:"mtls,omitempty"`
}

type APIKeyConfig struct {
	Key  string `json:"key"`
	In   string `json:"in,omitempty"`
	Name string `json:"name,omitempty"`
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

func (c Config) Validate(t Type) error {
	populated := 0
	if c.APIKey != nil {
		populated++
	}
	if c.OAuth2 != nil {
		populated++
	}
	if c.MTLS != nil {
		populated++
	}
	if populated != 1 {
		return fmt.Errorf("%w: exactly one config payload must be set", ErrInvalidConfig)
	}

	switch t {
	case TypeAPIKey:
		if c.APIKey == nil {
			return fmt.Errorf("%w: api_key config required for type %q", ErrInvalidConfig, t)
		}
		return c.APIKey.validate()
	case TypeOAuth2:
		if c.OAuth2 == nil {
			return fmt.Errorf("%w: oauth2 config required for type %q", ErrInvalidConfig, t)
		}
		return c.OAuth2.validate()
	case TypeMTLS:
		if c.MTLS == nil {
			return fmt.Errorf("%w: mtls config required for type %q", ErrInvalidConfig, t)
		}
		return c.MTLS.validate()
	default:
		return fmt.Errorf("%w: %q", ErrInvalidType, t)
	}
}

func (c APIKeyConfig) validate() error {
	if strings.TrimSpace(c.Key) == "" {
		return fmt.Errorf("%w: api_key.key is required", ErrInvalidConfig)
	}
	return nil
}

func (c OAuth2Config) validate() error {
	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: oauth2.issuer is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.JWKSURL) == "" && strings.TrimSpace(c.IntrospectionURL) == "" {
		return fmt.Errorf("%w: oauth2 requires jwks_url or introspection_url", ErrInvalidConfig)
	}
	return nil
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
