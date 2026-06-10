package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

type CreateAuthRequest struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Enabled *bool         `json:"enabled,omitempty"`
	Config  ConfigRequest `json:"config"`
}

type ConfigRequest struct {
	OAuth2       *OAuth2ConfigRequest       `json:"oauth2,omitempty"`
	OAuth2Client *OAuth2ClientConfigRequest `json:"oauth2_client,omitempty"`
	IDP          *IDPConfigRequest          `json:"idp,omitempty"`
	MTLS         *MTLSConfigRequest         `json:"mtls,omitempty"`
}

type OAuth2ConfigRequest struct {
	Issuer           string   `json:"issuer"`
	Audiences        []string `json:"audiences,omitempty"`
	JWKSURL          string   `json:"jwks_url,omitempty"`
	IntrospectionURL string   `json:"introspection_url,omitempty"`
	ClientID         string   `json:"client_id,omitempty"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	RequiredScopes   []string `json:"required_scopes,omitempty"`
	Algorithms       []string `json:"allowed_algorithms,omitempty"`
}

type OAuth2ClientConfigRequest struct {
	TokenURL     string   `json:"token_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes,omitempty"`
	Audience     string   `json:"audience,omitempty"`
}

type IDPConfigRequest struct {
	Issuer            string   `json:"issuer"`
	Audiences         []string `json:"audiences"`
	JWKSURL           string   `json:"jwks_url,omitempty"`
	PublicKeys        []string `json:"public_keys,omitempty"`
	RequiredScopes    []string `json:"required_scopes,omitempty"`
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	SubjectClaim      string   `json:"subject_claim,omitempty"`
}

type MTLSConfigRequest struct {
	CACert              string   `json:"ca_cert"`
	AllowedCommonNames  []string `json:"allowed_common_names,omitempty"`
	AllowedDNSNames     []string `json:"allowed_dns_names,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty"`
}

func (r CreateAuthRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Type) == "" {
		return fmt.Errorf("type is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreateAuthRequest) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func (c ConfigRequest) ToDomain() domain.Config {
	out := domain.Config{}
	if c.OAuth2 != nil {
		out.OAuth2 = &domain.OAuth2Config{
			Issuer:           c.OAuth2.Issuer,
			Audiences:        c.OAuth2.Audiences,
			JWKSURL:          c.OAuth2.JWKSURL,
			IntrospectionURL: c.OAuth2.IntrospectionURL,
			ClientID:         c.OAuth2.ClientID,
			ClientSecret:     c.OAuth2.ClientSecret,
			RequiredScopes:   c.OAuth2.RequiredScopes,
			Algorithms:       c.OAuth2.Algorithms,
		}
	}
	if c.OAuth2Client != nil {
		out.OAuth2Client = &domain.OAuth2ClientConfig{
			TokenURL:     c.OAuth2Client.TokenURL,
			ClientID:     c.OAuth2Client.ClientID,
			ClientSecret: c.OAuth2Client.ClientSecret,
			Scopes:       c.OAuth2Client.Scopes,
			Audience:     c.OAuth2Client.Audience,
		}
	}
	if c.IDP != nil {
		out.IDP = &domain.IDPConfig{
			Issuer:            c.IDP.Issuer,
			Audiences:         c.IDP.Audiences,
			JWKSURL:           c.IDP.JWKSURL,
			PublicKeys:        c.IDP.PublicKeys,
			RequiredScopes:    c.IDP.RequiredScopes,
			AllowedAlgorithms: c.IDP.AllowedAlgorithms,
			SubjectClaim:      c.IDP.SubjectClaim,
		}
	}
	if c.MTLS != nil {
		out.MTLS = &domain.MTLSConfig{
			CACert:              c.MTLS.CACert,
			AllowedCommonNames:  c.MTLS.AllowedCommonNames,
			AllowedDNSNames:     c.MTLS.AllowedDNSNames,
			AllowedFingerprints: c.MTLS.AllowedFingerprints,
		}
	}
	return out
}
