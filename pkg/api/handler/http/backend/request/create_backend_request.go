package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
)

type CreateBackendRequest struct {
	Name            string                  `json:"name"`
	Algorithm       string                  `json:"algorithm,omitempty"`
	Targets         []TargetRequest         `json:"targets"`
	EmbeddingConfig *EmbeddingConfigRequest `json:"embedding_config,omitempty"`
	HealthChecks    *HealthChecksRequest    `json:"health_checks,omitempty"`
}

type HealthChecksRequest struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threshold int               `json:"threshold"`
	Interval  int               `json:"interval"`
}

type TargetRequest struct {
	ID              string             `json:"id,omitempty"`
	Weight          int                `json:"weight,omitempty"`
	Provider        string             `json:"provider"`
	ProviderOptions map[string]any     `json:"provider_options,omitempty"`
	Description     string             `json:"description,omitempty"`
	Stream          bool               `json:"stream,omitempty"`
	Auth            *TargetAuthRequest `json:"auth,omitempty"`
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

type EmbeddingConfigRequest struct {
	Provider string             `json:"provider"`
	Model    string             `json:"model"`
	Auth     *APIKeyAuthRequest `json:"auth,omitempty"`
}

func (r CreateBackendRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("at least one target is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreateBackendRequest) ToTargets() domain.Targets {
	out := make(domain.Targets, 0, len(r.Targets))
	for _, tr := range r.Targets {
		out = append(out, tr.ToDomain())
	}
	return out
}

func (r CreateBackendRequest) ToEmbeddingConfig() *domain.EmbeddingConfig {
	if r.EmbeddingConfig == nil {
		return nil
	}
	return r.EmbeddingConfig.ToDomain()
}

func (r CreateBackendRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
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

func (t TargetRequest) ToDomain() domain.Target {
	return domain.Target{
		ID:              t.ID,
		Weight:          t.Weight,
		Provider:        t.Provider,
		ProviderOptions: t.ProviderOptions,
		Description:     t.Description,
		Stream:          t.Stream,
		Auth:            t.Auth.ToDomain(),
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

func (e *EmbeddingConfigRequest) ToDomain() *domain.EmbeddingConfig {
	if e == nil {
		return nil
	}
	return &domain.EmbeddingConfig{
		Provider: e.Provider,
		Model:    e.Model,
		Auth:     e.Auth.ToDomain(),
	}
}
