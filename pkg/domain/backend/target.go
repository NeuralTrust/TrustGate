package backend

import (
	"fmt"
)

type AuthType string

const (
	AuthTypeAPIKey            AuthType = "api_key"
	AuthTypeAzure             AuthType = "azure"
	AuthTypeAWS               AuthType = "aws"
	AuthTypeOAuth2            AuthType = "oauth2"
	AuthTypeGCPServiceAccount AuthType = "gcp_service_account"
)

type Target struct {
	ID              string         `json:"id"`
	Weight          int            `json:"weight,omitempty"`
	Provider        string         `json:"provider"`
	ProviderOptions map[string]any `json:"provider_options,omitempty"`
	Description     string         `json:"description,omitempty"`
	Stream          bool           `json:"stream,omitempty"`
	Auth            *TargetAuth    `json:"auth,omitempty"`
}

type TargetAuth struct {
	Type              AuthType           `json:"type"`
	APIKey            *APIKeyAuth        `json:"api_key,omitempty"`
	Azure             *AzureAuth         `json:"azure,omitempty"`
	AWS               *AWSAuth           `json:"aws,omitempty"`
	OAuth             *TargetOAuthConfig `json:"oauth,omitempty"`
	GCPServiceAccount *string            `json:"gcp_service_account,omitempty"`
}

type APIKeyAuth struct {
	APIKey        string `json:"api_key,omitempty"` // #nosec G117 -- upstream credential
	HeaderName    string `json:"header_name,omitempty"`
	HeaderValue   string `json:"header_value,omitempty"`
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"`
}

type AzureAuth struct {
	UseManagedIdentity bool   `json:"use_managed_identity,omitempty"`
	Endpoint           string `json:"endpoint,omitempty"`
	Version            string `json:"version,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	ClientSecret       string `json:"client_secret,omitempty"` // #nosec G117 -- Azure client secret
	TenantID           string `json:"tenant_id,omitempty"`
}

type AWSAuth struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"` // #nosec G117 -- AWS secret
	Region          string `json:"region,omitempty"`
	SessionToken    string `json:"session_token,omitempty"` // #nosec G117 -- AWS session token
	Role            string `json:"role,omitempty"`
	UseRole         bool   `json:"use_role,omitempty"`
}

type TargetOAuthConfig struct {
	TokenURL     string            `json:"token_url"`
	GrantType    string            `json:"grant_type"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"` // #nosec G117 -- OAuth client credentials flow
	UseBasicAuth bool              `json:"use_basic_auth,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Audience     string            `json:"audience,omitempty"`
	Code         string            `json:"code,omitempty"`
	RedirectURI  string            `json:"redirect_uri,omitempty"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"` // #nosec G117 -- OAuth refresh token flow
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"` // #nosec G117 -- OAuth password grant
	Extra        map[string]string `json:"extra,omitempty"`
}

// NewAPIKeyAuth builds a TargetAuth for the common bearer-key case.
func NewAPIKeyAuth(apiKey string) *TargetAuth {
	return &TargetAuth{
		Type:   AuthTypeAPIKey,
		APIKey: &APIKeyAuth{APIKey: apiKey},
	}
}

func NewOAuth2Auth(config *TargetOAuthConfig) *TargetAuth {
	return &TargetAuth{
		Type:  AuthTypeOAuth2,
		OAuth: config,
	}
}

func NewGCPServiceAccountAuth(encryptedSA string) *TargetAuth {
	return &TargetAuth{
		Type:              AuthTypeGCPServiceAccount,
		GCPServiceAccount: &encryptedSA,
	}
}

func (t *Target) Validate() error {
	if t.Weight < 0 {
		return fmt.Errorf("%w: weight cannot be negative", ErrInvalidTarget)
	}
	if t.Provider == "" {
		return fmt.Errorf("%w: provider is required", ErrInvalidTarget)
	}
	if t.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidTarget)
	}
	return t.Auth.Validate()
}

func (a *TargetAuth) Validate() error {
	switch a.Type {
	case AuthTypeAPIKey:
		if a.APIKey == nil {
			return fmt.Errorf("%w: api_key payload required for type api_key", ErrInvalidTarget)
		}
		if a.APIKey.APIKey == "" && (a.APIKey.HeaderName == "" || a.APIKey.HeaderValue == "") &&
			(a.APIKey.ParamName == "" || a.APIKey.ParamValue == "") {
			return fmt.Errorf("%w: api_key requires api_key, header pair, or param pair", ErrInvalidTarget)
		}
	case AuthTypeAzure:
		if a.Azure == nil {
			return fmt.Errorf("%w: azure payload required for type azure", ErrInvalidTarget)
		}
	case AuthTypeAWS:
		if a.AWS == nil {
			return fmt.Errorf("%w: aws payload required for type aws", ErrInvalidTarget)
		}
	case AuthTypeOAuth2:
		if a.OAuth == nil {
			return fmt.Errorf("%w: oauth configuration required for type oauth2", ErrInvalidTarget)
		}
		if a.OAuth.TokenURL == "" {
			return fmt.Errorf("%w: oauth.token_url is required", ErrInvalidTarget)
		}
		if a.OAuth.GrantType == "" {
			return fmt.Errorf("%w: oauth.grant_type is required", ErrInvalidTarget)
		}
	case AuthTypeGCPServiceAccount:
		if a.GCPServiceAccount == nil || *a.GCPServiceAccount == "" {
			return fmt.Errorf("%w: gcp_service_account payload required", ErrInvalidTarget)
		}
	default:
		return fmt.Errorf("%w: unknown auth type %q", ErrInvalidTarget, a.Type)
	}
	return nil
}
