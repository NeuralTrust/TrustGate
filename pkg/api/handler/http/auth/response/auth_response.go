package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type AuthResponse struct {
	ID        ids.AuthID     `json:"id"`
	GatewayID ids.GatewayID  `json:"gateway_id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Enabled   bool           `json:"enabled"`
	Config    ConfigResponse `json:"config"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ConfigResponse struct {
	APIKey *APIKeyConfigResponse `json:"api_key,omitempty"`
	OAuth2 *OAuth2ConfigResponse `json:"oauth2,omitempty"`
	MTLS   *MTLSConfigResponse   `json:"mtls,omitempty"`
}

type APIKeyConfigResponse struct {
	Key  string `json:"key,omitempty"` // #nosec G117
	In   string `json:"in,omitempty"`
	Name string `json:"name,omitempty"`
}

type OAuth2ConfigResponse struct {
	Issuer           string   `json:"issuer"`
	Audiences        []string `json:"audiences,omitempty"`
	JWKSURL          string   `json:"jwks_url,omitempty"`
	IntrospectionURL string   `json:"introspection_url,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	RequiredScopes   []string `json:"required_scopes,omitempty"`
	Algorithms       []string `json:"allowed_algorithms,omitempty"`
}

type MTLSConfigResponse struct {
	CACert              string   `json:"ca_cert,omitempty"`
	AllowedCommonNames  []string `json:"allowed_common_names,omitempty"`
	AllowedDNSNames     []string `json:"allowed_dns_names,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty"`
}

// maskSecret partially reveals a secret so the API never returns it in full.
// Short secrets are fully redacted; longer ones keep their first two and last
// three characters (e.g. "ab...xyz").
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) < 8 {
		return "***"
	}
	return s[:2] + "..." + s[len(s)-3:]
}

func FromAuth(a *domain.Auth) AuthResponse {
	return AuthResponse{
		ID:        a.ID,
		GatewayID: a.GatewayID,
		Name:      a.Name,
		Type:      string(a.Type),
		Enabled:   a.Enabled,
		Config:    fromConfig(a.Config),
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	}
}

func fromConfig(c domain.Config) ConfigResponse {
	out := ConfigResponse{}
	if c.APIKey != nil {
		out.APIKey = &APIKeyConfigResponse{
			Key:  maskSecret(c.APIKey.Key),
			In:   c.APIKey.In,
			Name: c.APIKey.Name,
		}
	}
	if c.OAuth2 != nil {
		out.OAuth2 = &OAuth2ConfigResponse{
			Issuer:           c.OAuth2.Issuer,
			Audiences:        c.OAuth2.Audiences,
			JWKSURL:          c.OAuth2.JWKSURL,
			IntrospectionURL: c.OAuth2.IntrospectionURL,
			ClientID:         c.OAuth2.ClientID,
			ClientSecret:     maskSecret(c.OAuth2.ClientSecret),
			RequiredScopes:   c.OAuth2.RequiredScopes,
			Algorithms:       c.OAuth2.Algorithms,
		}
	}
	if c.MTLS != nil {
		out.MTLS = &MTLSConfigResponse{
			CACert:              c.MTLS.CACert,
			AllowedCommonNames:  c.MTLS.AllowedCommonNames,
			AllowedDNSNames:     c.MTLS.AllowedDNSNames,
			AllowedFingerprints: c.MTLS.AllowedFingerprints,
		}
	}
	return out
}
