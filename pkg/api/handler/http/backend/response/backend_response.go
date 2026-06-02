package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

const redacted = "***"

type BackendResponse struct {
	ID              ids.BackendID         `json:"id"`
	GatewayID       ids.GatewayID         `json:"gateway_id"`
	Name            string                `json:"name"`
	Provider        string                `json:"provider"`
	ProviderOptions map[string]any        `json:"provider_options,omitempty"`
	Description     string                `json:"description,omitempty"`
	Weight          int                   `json:"weight,omitempty"`
	Auth            *TargetAuthResponse   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksResponse `json:"health_checks,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type HealthChecksResponse struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threshold int               `json:"threshold"`
	Interval  int               `json:"interval"`
}

type TargetAuthResponse struct {
	Type              string                     `json:"type"`
	APIKey            *APIKeyAuthResponse        `json:"api_key,omitempty"`
	Azure             *AzureAuthResponse         `json:"azure,omitempty"`
	AWS               *AWSAuthResponse           `json:"aws,omitempty"`
	OAuth             *TargetOAuthConfigResponse `json:"oauth,omitempty"`
	GCPServiceAccount *string                    `json:"gcp_service_account,omitempty"`
}

type APIKeyAuthResponse struct {
	APIKey        string `json:"api_key,omitempty"` // #nosec G117
	HeaderName    string `json:"header_name,omitempty"`
	HeaderValue   string `json:"header_value,omitempty"`
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"`
}

type AzureAuthResponse struct {
	UseManagedIdentity bool   `json:"use_managed_identity,omitempty"`
	Endpoint           string `json:"endpoint,omitempty"`
	Version            string `json:"version,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	ClientSecret       string `json:"client_secret,omitempty"` // #nosec G117
	TenantID           string `json:"tenant_id,omitempty"`
}

type AWSAuthResponse struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"` // #nosec G117
	Region          string `json:"region,omitempty"`
	SessionToken    string `json:"session_token,omitempty"` // #nosec G117
	Role            string `json:"role,omitempty"`
	UseRole         bool   `json:"use_role,omitempty"`
}

type TargetOAuthConfigResponse struct {
	TokenURL     string            `json:"token_url"`
	GrantType    string            `json:"grant_type"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"` // #nosec G117
	UseBasicAuth bool              `json:"use_basic_auth,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Audience     string            `json:"audience,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"` // #nosec G117
	Extra        map[string]string `json:"extra,omitempty"`
}

func FromBackend(b *domain.Backend) BackendResponse {
	var health *HealthChecksResponse
	if b.HealthChecks != nil {
		health = &HealthChecksResponse{
			Passive:   b.HealthChecks.Passive,
			Path:      b.HealthChecks.Path,
			Headers:   b.HealthChecks.Headers,
			Threshold: b.HealthChecks.Threshold,
			Interval:  b.HealthChecks.Interval,
		}
	}
	return BackendResponse{
		ID:              b.ID,
		GatewayID:       b.GatewayID,
		Name:            b.Name,
		Provider:        b.Provider,
		ProviderOptions: b.ProviderOptions,
		Description:     b.Description,
		Weight:          b.Weight,
		Auth:            FromAuth(b.Auth),
		HealthChecks:    health,
		CreatedAt:       b.CreatedAt,
		UpdatedAt:       b.UpdatedAt,
	}
}

func FromAuth(a *domain.TargetAuth) *TargetAuthResponse {
	if a == nil {
		return nil
	}
	out := &TargetAuthResponse{Type: string(a.Type)}
	if a.GCPServiceAccount != nil {
		gcp := redacted
		out.GCPServiceAccount = &gcp
	}
	out.APIKey = fromAPIKeyAuth(a.APIKey)
	out.Azure = fromAzureAuth(a.Azure)
	out.AWS = fromAWSAuth(a.AWS)
	out.OAuth = fromOAuthConfig(a.OAuth)
	return out
}

func fromAPIKeyAuth(k *domain.APIKeyAuth) *APIKeyAuthResponse {
	if k == nil {
		return nil
	}
	return &APIKeyAuthResponse{
		APIKey:        redactIfPresent(k.APIKey),
		HeaderName:    k.HeaderName,
		HeaderValue:   redactIfPresent(k.HeaderValue),
		ParamName:     k.ParamName,
		ParamValue:    redactIfPresent(k.ParamValue),
		ParamLocation: k.ParamLocation,
	}
}

func fromAzureAuth(a *domain.AzureAuth) *AzureAuthResponse {
	if a == nil {
		return nil
	}
	return &AzureAuthResponse{
		UseManagedIdentity: a.UseManagedIdentity,
		Endpoint:           a.Endpoint,
		Version:            a.Version,
		ClientID:           a.ClientID,
		ClientSecret:       redactIfPresent(a.ClientSecret),
		TenantID:           a.TenantID,
	}
}

func fromAWSAuth(a *domain.AWSAuth) *AWSAuthResponse {
	if a == nil {
		return nil
	}
	return &AWSAuthResponse{
		AccessKeyID:     redactIfPresent(a.AccessKeyID),
		SecretAccessKey: redactIfPresent(a.SecretAccessKey),
		Region:          a.Region,
		SessionToken:    redactIfPresent(a.SessionToken),
		Role:            a.Role,
		UseRole:         a.UseRole,
	}
}

func fromOAuthConfig(o *domain.TargetOAuthConfig) *TargetOAuthConfigResponse {
	if o == nil {
		return nil
	}
	return &TargetOAuthConfigResponse{
		TokenURL:     o.TokenURL,
		GrantType:    o.GrantType,
		ClientID:     o.ClientID,
		ClientSecret: redactIfPresent(o.ClientSecret),
		UseBasicAuth: o.UseBasicAuth,
		Scopes:       o.Scopes,
		Audience:     o.Audience,
		RefreshToken: redactIfPresent(o.RefreshToken),
		Extra:        o.Extra,
	}
}

func redactIfPresent(v string) string {
	if v == "" {
		return ""
	}
	return redacted
}
