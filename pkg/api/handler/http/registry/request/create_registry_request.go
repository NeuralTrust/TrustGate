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

package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type CreateRegistryRequest struct {
	Name            string               `json:"name"`
	Type            string               `json:"type,omitempty"`
	Enabled         *bool                `json:"enabled,omitempty"`
	Provider        string               `json:"provider,omitempty"`
	ProviderOptions map[string]any       `json:"provider_options,omitempty"`
	Description     string               `json:"description,omitempty"`
	Auth            *TargetAuthRequest   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksRequest `json:"health_checks,omitempty"`
	MCPTarget       *MCPTargetRequest    `json:"mcp_target,omitempty"`
}

type MCPTargetRequest struct {
	Code      string            `json:"code,omitempty"`
	URL       string            `json:"url"`
	Transport string            `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Auth      *MCPAuthRequest   `json:"auth,omitempty"`
}

type MCPAuthRequest struct {
	Mode   string `json:"mode"`
	Header string `json:"header,omitempty"`
	Value  string `json:"value,omitempty"` // #nosec G117

	ExpectedAudience string `json:"expected_audience,omitempty"`

	Pattern  string `json:"pattern,omitempty"`
	Audience string `json:"audience,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Actor    string `json:"actor,omitempty"`

	Provider     string   `json:"provider,omitempty"`
	Registration string   `json:"registration,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"` // #nosec G117
	AuthorizeURL string   `json:"authorize_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Resource     string   `json:"resource,omitempty"`
}

type HealthChecksRequest struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threshold int               `json:"threshold"`
	Interval  int               `json:"interval"`
}

type TargetAuthRequest struct {
	Type              string                    `json:"type"`
	APIKey            *APIKeyAuthRequest        `json:"api_key,omitempty"`
	Azure             *AzureAuthRequest         `json:"azure,omitempty"`
	AWS               *AWSAuthRequest           `json:"aws,omitempty"`
	OAuth             *TargetOAuthConfigRequest `json:"oauth,omitempty"`
	GCPServiceAccount *string                   `json:"gcp_service_account,omitempty"`
}

type APIKeyAuthRequest struct {
	APIKey        string `json:"api_key,omitempty"` // #nosec G117
	HeaderName    string `json:"header_name,omitempty"`
	HeaderValue   string `json:"header_value,omitempty"`
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"`
}

type AzureAuthRequest struct {
	UseManagedIdentity bool   `json:"use_managed_identity,omitempty"`
	Endpoint           string `json:"endpoint,omitempty"`
	Version            string `json:"version,omitempty"`
	APIKey             string `json:"api_key,omitempty"` // #nosec G117
	ClientID           string `json:"client_id,omitempty"`
	ClientSecret       string `json:"client_secret,omitempty"` // #nosec G117
	TenantID           string `json:"tenant_id,omitempty"`
}

type AWSAuthRequest struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"` // #nosec G117
	Region          string `json:"region,omitempty"`
	SessionToken    string `json:"session_token,omitempty"` // #nosec G117
	Role            string `json:"role,omitempty"`
	UseRole         bool   `json:"use_role,omitempty"`
}

type TargetOAuthConfigRequest struct {
	TokenURL     string            `json:"token_url"`
	GrantType    string            `json:"grant_type"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"` // #nosec G117
	UseBasicAuth bool              `json:"use_basic_auth,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Audience     string            `json:"audience,omitempty"`
	Code         string            `json:"code,omitempty"`
	RedirectURI  string            `json:"redirect_uri,omitempty"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"` // #nosec G117
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"` // #nosec G117
	Extra        map[string]string `json:"extra,omitempty"`
}

func (r CreateRegistryRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if r.ToType() == domain.TypeMCP {
		if r.MCPTarget == nil {
			return fmt.Errorf("mcp_target is required for MCP registries: %w", commonerrors.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(r.Provider) == "" {
		return fmt.Errorf("provider is required: %w", commonerrors.ErrValidation)
	}
	if r.Auth == nil {
		return fmt.Errorf("auth is required: %w", commonerrors.ErrValidation)
	}
	if err := r.Auth.ToDomain().Validate(); err != nil {
		return err
	}
	return nil
}

func (r CreateRegistryRequest) ToType() domain.Type {
	if r.Type == "" {
		return domain.TypeLLM
	}
	return domain.Type(strings.ToUpper(strings.TrimSpace(r.Type)))
}

func (r CreateRegistryRequest) ToLLMTarget() *domain.LLMTarget {
	if r.ToType() != domain.TypeLLM && r.Provider == "" && len(r.ProviderOptions) == 0 && r.Auth == nil && r.HealthChecks == nil {
		return nil
	}
	return &domain.LLMTarget{
		Provider:        r.Provider,
		ProviderOptions: r.ProviderOptions,
		Auth:            r.Auth.ToDomain(),
		HealthChecks:    r.HealthChecks.ToDomain(),
	}
}

func (r CreateRegistryRequest) ToMCPTarget() *domain.MCPTarget {
	return r.MCPTarget.ToDomain()
}

func (t *MCPTargetRequest) ToDomain() *domain.MCPTarget {
	if t == nil {
		return nil
	}
	out := &domain.MCPTarget{
		Code:      t.Code,
		URL:       t.URL,
		Transport: domain.MCPTransport(t.Transport),
		Headers:   t.Headers,
	}
	if t.Auth != nil {
		out.Auth = &domain.MCPAuth{
			Mode:             domain.MCPAuthMode(t.Auth.Mode),
			Header:           t.Auth.Header,
			Value:            t.Auth.Value,
			ExpectedAudience: t.Auth.ExpectedAudience,
			Pattern:          domain.MCPExchangePattern(t.Auth.Pattern),
			Audience:         t.Auth.Audience,
			Scope:            t.Auth.Scope,
			Actor:            t.Auth.Actor,
			Provider:         t.Auth.Provider,
			Registration:     domain.MCPClientRegistration(t.Auth.Registration),
			ClientID:         t.Auth.ClientID,
			ClientSecret:     t.Auth.ClientSecret,
			AuthorizeURL:     t.Auth.AuthorizeURL,
			TokenURL:         t.Auth.TokenURL,
			Scopes:           t.Auth.Scopes,
			Resource:         t.Auth.Resource,
		}
	}
	return out
}

func (h *HealthChecksRequest) ToDomain() *domain.HealthChecks {
	if h == nil {
		return nil
	}
	return &domain.HealthChecks{
		Passive:   h.Passive,
		Path:      h.Path,
		Headers:   h.Headers,
		Threshold: h.Threshold,
		Interval:  h.Interval,
	}
}

func (a *TargetAuthRequest) ToDomain() *domain.TargetAuth {
	if a == nil {
		return nil
	}
	out := &domain.TargetAuth{
		Type:              domain.AuthType(a.Type),
		GCPServiceAccount: a.GCPServiceAccount,
	}
	if a.APIKey != nil {
		out.APIKey = a.APIKey.ToDomain()
	}
	if a.Azure != nil {
		out.Azure = a.Azure.ToDomain()
	}
	if a.AWS != nil {
		out.AWS = a.AWS.ToDomain()
	}
	if a.OAuth != nil {
		out.OAuth = a.OAuth.ToDomain()
	}
	return out
}

func (k *APIKeyAuthRequest) ToDomain() *domain.APIKeyAuth {
	if k == nil {
		return nil
	}
	return &domain.APIKeyAuth{
		APIKey:        k.APIKey,
		HeaderName:    k.HeaderName,
		HeaderValue:   k.HeaderValue,
		ParamName:     k.ParamName,
		ParamValue:    k.ParamValue,
		ParamLocation: k.ParamLocation,
	}
}

func (a *AzureAuthRequest) ToDomain() *domain.AzureAuth {
	if a == nil {
		return nil
	}
	return &domain.AzureAuth{
		UseManagedIdentity: a.UseManagedIdentity,
		Endpoint:           a.Endpoint,
		Version:            a.Version,
		APIKey:             a.APIKey,
		ClientID:           a.ClientID,
		ClientSecret:       a.ClientSecret,
		TenantID:           a.TenantID,
	}
}

func (a *AWSAuthRequest) ToDomain() *domain.AWSAuth {
	if a == nil {
		return nil
	}
	return &domain.AWSAuth{
		AccessKeyID:     a.AccessKeyID,
		SecretAccessKey: a.SecretAccessKey,
		Region:          a.Region,
		SessionToken:    a.SessionToken,
		Role:            a.Role,
		UseRole:         a.UseRole,
	}
}

func (o *TargetOAuthConfigRequest) ToDomain() *domain.TargetOAuthConfig {
	if o == nil {
		return nil
	}
	return &domain.TargetOAuthConfig{
		TokenURL:     o.TokenURL,
		GrantType:    o.GrantType,
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		UseBasicAuth: o.UseBasicAuth,
		Scopes:       o.Scopes,
		Audience:     o.Audience,
		Code:         o.Code,
		RedirectURI:  o.RedirectURI,
		CodeVerifier: o.CodeVerifier,
		RefreshToken: o.RefreshToken,
		Username:     o.Username,
		Password:     o.Password,
		Extra:        o.Extra,
	}
}
