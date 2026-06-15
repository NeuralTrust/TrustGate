package response

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type RegistryResponse struct {
	ID              ids.RegistryID        `json:"id"`
	GatewayID       ids.GatewayID         `json:"gateway_id"`
	Name            string                `json:"name"`
	Type            string                `json:"type"`
	Provider        string                `json:"provider,omitempty"`
	ProviderOptions map[string]any        `json:"provider_options,omitempty"`
	Description     string                `json:"description,omitempty"`
	Auth            *TargetAuthResponse   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksResponse `json:"health_checks,omitempty"`
	MCPTarget       *MCPTargetResponse    `json:"mcp_target,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

type MCPTargetResponse struct {
	URL       string            `json:"url"`
	Transport string            `json:"transport,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Auth      *MCPAuthResponse  `json:"auth,omitempty"`
}

type MCPAuthResponse struct {
	Mode   string `json:"mode"`
	Header string `json:"header,omitempty"`
	Value  string `json:"value,omitempty"` // #nosec G117 -- masked before serialization

	ExpectedAudience string `json:"expected_audience,omitempty"`

	Pattern  string `json:"pattern,omitempty"`
	Audience string `json:"audience,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Actor    string `json:"actor,omitempty"`

	Provider     string   `json:"provider,omitempty"`
	Registration string   `json:"registration,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"` // #nosec G117 -- masked before serialization
	AuthorizeURL string   `json:"authorize_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Resource     string   `json:"resource,omitempty"`
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
	APIKey             string `json:"api_key,omitempty"` // #nosec G117
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

func FromRegistry(b *domain.Registry) RegistryResponse {
	var health *HealthChecksResponse
	if hc := b.HealthChecks(); hc != nil {
		health = &HealthChecksResponse{
			Passive:   hc.Passive,
			Path:      hc.Path,
			Headers:   hc.Headers,
			Threshold: hc.Threshold,
			Interval:  hc.Interval,
		}
	}
	regType := b.Type
	if regType == "" {
		regType = domain.TypeLLM
	}
	return RegistryResponse{
		ID:              b.ID,
		GatewayID:       b.GatewayID,
		Name:            b.Name,
		Type:            string(regType),
		Provider:        b.Provider(),
		ProviderOptions: b.ProviderOptions(),
		Description:     b.Description,
		Auth:            FromAuth(b.Auth()),
		HealthChecks:    health,
		MCPTarget:       fromMCPTarget(b.MCPTarget),
		CreatedAt:       b.CreatedAt,
		UpdatedAt:       b.UpdatedAt,
	}
}

func fromMCPTarget(t *domain.MCPTarget) *MCPTargetResponse {
	if t == nil {
		return nil
	}
	out := &MCPTargetResponse{
		URL:       t.URL,
		Transport: string(t.Transport),
		Headers:   t.Headers,
	}
	if t.Auth != nil {
		out.Auth = &MCPAuthResponse{
			Mode:             string(t.Auth.Mode),
			Header:           t.Auth.Header,
			Value:            secret.Mask(t.Auth.Value),
			ExpectedAudience: t.Auth.ExpectedAudience,
			Pattern:          string(t.Auth.Pattern),
			Audience:         t.Auth.Audience,
			Scope:            t.Auth.Scope,
			Actor:            t.Auth.Actor,
			Provider:         t.Auth.Provider,
			Registration:     string(t.Auth.Registration),
			ClientID:         t.Auth.ClientID,
			ClientSecret:     secret.Mask(t.Auth.ClientSecret),
			AuthorizeURL:     t.Auth.AuthorizeURL,
			TokenURL:         t.Auth.TokenURL,
			Scopes:           t.Auth.Scopes,
			Resource:         t.Auth.Resource,
		}
	}
	return out
}

func FromAuth(a *domain.TargetAuth) *TargetAuthResponse {
	if a == nil {
		return nil
	}
	out := &TargetAuthResponse{Type: string(a.Type)}
	if a.GCPServiceAccount != nil {
		gcp := secret.Mask(*a.GCPServiceAccount)
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
		APIKey:        secret.Mask(k.APIKey),
		HeaderName:    k.HeaderName,
		HeaderValue:   secret.Mask(k.HeaderValue),
		ParamName:     k.ParamName,
		ParamValue:    secret.Mask(k.ParamValue),
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
		APIKey:             secret.Mask(a.APIKey),
		ClientID:           a.ClientID,
		ClientSecret:       secret.Mask(a.ClientSecret),
		TenantID:           a.TenantID,
	}
}

func fromAWSAuth(a *domain.AWSAuth) *AWSAuthResponse {
	if a == nil {
		return nil
	}
	return &AWSAuthResponse{
		AccessKeyID:     secret.Mask(a.AccessKeyID),
		SecretAccessKey: secret.Mask(a.SecretAccessKey),
		Region:          a.Region,
		SessionToken:    secret.Mask(a.SessionToken),
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
		ClientSecret: secret.Mask(o.ClientSecret),
		UseBasicAuth: o.UseBasicAuth,
		Scopes:       o.Scopes,
		Audience:     o.Audience,
		RefreshToken: secret.Mask(o.RefreshToken),
		Extra:        o.Extra,
	}
}
