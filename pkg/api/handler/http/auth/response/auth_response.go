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

package response

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type AuthResponse struct {
	ID        ids.AuthID     `json:"id"`
	GatewayID ids.GatewayID  `json:"gateway_id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Enabled   bool           `json:"enabled"`
	Config    ConfigResponse `json:"config"`
	APIKey    string         `json:"api_key,omitempty"` // #nosec G101
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ConfigResponse struct {
	OAuth2 *OAuth2ConfigResponse `json:"oauth2,omitempty"`
	OIDC   *OIDCConfigResponse    `json:"oidc,omitempty"`
	MTLS   *MTLSConfigResponse   `json:"mtls,omitempty"`
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

type OIDCConfigResponse struct {
	Issuer            string   `json:"issuer"`
	Audiences         []string `json:"audiences"`
	JWKSURL           string   `json:"jwks_url,omitempty"`
	PublicKeys        []string `json:"public_keys,omitempty"`
	RequiredScopes    []string `json:"required_scopes,omitempty"`
	AllowedAlgorithms []string `json:"allowed_algorithms,omitempty"`
	SubjectClaim      string   `json:"subject_claim,omitempty"`
}

type MTLSConfigResponse struct {
	CACert              string   `json:"ca_cert,omitempty"`
	AllowedCommonNames  []string `json:"allowed_common_names,omitempty"`
	AllowedDNSNames     []string `json:"allowed_dns_names,omitempty"`
	AllowedFingerprints []string `json:"allowed_fingerprints,omitempty"`
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

func FromCreatedAuth(a *domain.Auth) AuthResponse {
	res := FromAuth(a)
	res.APIKey = a.RawKey
	return res
}

func fromConfig(c domain.Config) ConfigResponse {
	out := ConfigResponse{}
	if c.OAuth2 != nil {
		out.OAuth2 = &OAuth2ConfigResponse{
			Issuer:           c.OAuth2.Issuer,
			Audiences:        c.OAuth2.Audiences,
			JWKSURL:          c.OAuth2.JWKSURL,
			IntrospectionURL: c.OAuth2.IntrospectionURL,
			ClientID:         c.OAuth2.ClientID,
			ClientSecret:     secret.Mask(c.OAuth2.ClientSecret),
			RequiredScopes:   c.OAuth2.RequiredScopes,
			Algorithms:       c.OAuth2.Algorithms,
		}
	}
	if c.OIDC != nil {
		out.OIDC = &OIDCConfigResponse{
			Issuer:            c.OIDC.Issuer,
			Audiences:         c.OIDC.Audiences,
			JWKSURL:           c.OIDC.JWKSURL,
			PublicKeys:        c.OIDC.PublicKeys,
			RequiredScopes:    c.OIDC.RequiredScopes,
			AllowedAlgorithms: c.OIDC.AllowedAlgorithms,
			SubjectClaim:      c.OIDC.SubjectClaim,
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
