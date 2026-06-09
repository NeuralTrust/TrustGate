package registry

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

type AuthType string

const (
	AuthTypeAPIKey            AuthType = "api_key"
	AuthTypeAzure             AuthType = "azure"
	AuthTypeAWS               AuthType = "aws"
	AuthTypeOAuth2            AuthType = "oauth2"
	AuthTypeGCPServiceAccount AuthType = "gcp_service_account"
)

type AzureCredentialMode string

const (
	AzureCredentialModeAPIKey                 AzureCredentialMode = "api_key"
	AzureCredentialModeServicePrincipal       AzureCredentialMode = "service_principal"
	AzureCredentialModeDefaultAzureCredential AzureCredentialMode = "default_azure_credential"
)

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
	APIKey             string `json:"api_key,omitempty"` // #nosec G117 -- Azure OpenAI api-key credential
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

// ResolveSecretsFrom keeps previously stored secret values when the incoming
// update omits them (empty or the redaction placeholder). It only merges when the
// auth type is unchanged; switching types requires supplying the new secrets.
func (a *TargetAuth) ResolveSecretsFrom(prev *TargetAuth) {
	if a == nil || prev == nil || a.Type != prev.Type {
		return
	}
	switch a.Type {
	case AuthTypeAPIKey:
		if a.APIKey != nil && prev.APIKey != nil {
			a.APIKey.APIKey = secret.Resolve(a.APIKey.APIKey, prev.APIKey.APIKey)
			a.APIKey.HeaderValue = secret.Resolve(a.APIKey.HeaderValue, prev.APIKey.HeaderValue)
			a.APIKey.ParamValue = secret.Resolve(a.APIKey.ParamValue, prev.APIKey.ParamValue)
		}
	case AuthTypeAzure:
		if a.Azure != nil && prev.Azure != nil {
			a.Azure.ResolveSecretsFrom(prev.Azure)
		}
	case AuthTypeAWS:
		if a.AWS != nil && prev.AWS != nil {
			a.AWS.AccessKeyID = secret.Resolve(a.AWS.AccessKeyID, prev.AWS.AccessKeyID)
			a.AWS.SecretAccessKey = secret.Resolve(a.AWS.SecretAccessKey, prev.AWS.SecretAccessKey)
			a.AWS.SessionToken = secret.Resolve(a.AWS.SessionToken, prev.AWS.SessionToken)
		}
	case AuthTypeOAuth2:
		if a.OAuth != nil && prev.OAuth != nil {
			a.OAuth.ClientSecret = secret.Resolve(a.OAuth.ClientSecret, prev.OAuth.ClientSecret)
			a.OAuth.RefreshToken = secret.Resolve(a.OAuth.RefreshToken, prev.OAuth.RefreshToken)
			a.OAuth.Password = secret.Resolve(a.OAuth.Password, prev.OAuth.Password)
		}
	case AuthTypeGCPServiceAccount:
		if prev.GCPServiceAccount != nil && blankSecretPtr(a.GCPServiceAccount) {
			a.GCPServiceAccount = prev.GCPServiceAccount
		}
	}
}

func (a *AzureAuth) ResolveSecretsFrom(prev *AzureAuth) {
	if a == nil || prev == nil {
		return
	}
	mode, ok, ambiguous := a.updateCredentialMode(prev)
	if ambiguous || !ok {
		return
	}
	prevMode, prevModeErr := prev.CredentialMode()
	prevModeOK := prevModeErr == nil
	switch mode {
	case AzureCredentialModeAPIKey:
		if prevModeOK && prevMode == AzureCredentialModeAPIKey {
			a.APIKey = secret.Resolve(a.APIKey, prev.APIKey)
		}
		a.ClientID = ""
		a.ClientSecret = ""
		a.TenantID = ""
		a.UseManagedIdentity = false
	case AzureCredentialModeServicePrincipal:
		if a.ClientID == "" {
			a.ClientID = prev.ClientID
		}
		if a.TenantID == "" {
			a.TenantID = prev.TenantID
		}
		if prevModeOK && prevMode == AzureCredentialModeServicePrincipal &&
			a.ClientID == prev.ClientID && a.TenantID == prev.TenantID {
			a.ClientSecret = secret.Resolve(a.ClientSecret, prev.ClientSecret)
		}
		a.APIKey = ""
		a.UseManagedIdentity = false
	case AzureCredentialModeDefaultAzureCredential:
		a.APIKey = ""
		a.ClientID = ""
		a.ClientSecret = ""
		a.TenantID = ""
		a.UseManagedIdentity = true
	}
}

func (a *AzureAuth) updateCredentialMode(prev *AzureAuth) (AzureCredentialMode, bool, bool) {
	apiKeyMode := hasSecretInput(a.APIKey)
	servicePrincipalMode := strings.TrimSpace(a.ClientID) != "" ||
		strings.TrimSpace(a.TenantID) != "" ||
		hasSecretInput(a.ClientSecret)
	defaultAzureCredentialMode := a.UseManagedIdentity

	modeCount := 0
	if apiKeyMode {
		modeCount++
	}
	if servicePrincipalMode {
		modeCount++
	}
	if defaultAzureCredentialMode {
		modeCount++
	}
	if modeCount > 1 {
		return "", false, true
	}
	if apiKeyMode {
		return AzureCredentialModeAPIKey, true, false
	}
	if servicePrincipalMode {
		return AzureCredentialModeServicePrincipal, true, false
	}
	if defaultAzureCredentialMode {
		return AzureCredentialModeDefaultAzureCredential, true, false
	}
	mode, err := prev.CredentialMode()
	if err != nil {
		return "", false, false
	}
	return mode, true, false
}

func hasSecretInput(v string) bool {
	return strings.TrimSpace(v) != "" || secret.IsMasked(v)
}

func blankSecretPtr(s *string) bool {
	return s == nil || *s == "" || secret.IsMasked(*s)
}

// secretValues returns every secret field that the API masks in responses, so
// Validate can reject the redaction placeholder before it is persisted.
func (a *TargetAuth) secretValues() []string {
	var v []string
	if a.APIKey != nil {
		v = append(v, a.APIKey.APIKey, a.APIKey.HeaderValue, a.APIKey.ParamValue)
	}
	if a.Azure != nil {
		v = append(v, a.Azure.APIKey, a.Azure.ClientSecret)
	}
	if a.AWS != nil {
		v = append(v, a.AWS.AccessKeyID, a.AWS.SecretAccessKey, a.AWS.SessionToken)
	}
	if a.OAuth != nil {
		v = append(v, a.OAuth.ClientSecret, a.OAuth.RefreshToken, a.OAuth.Password)
	}
	if a.GCPServiceAccount != nil {
		v = append(v, *a.GCPServiceAccount)
	}
	return v
}

func (a *TargetAuth) ProviderCredentials() providers.Credentials {
	creds := providers.Credentials{}
	if a == nil {
		return creds
	}
	switch a.Type {
	case AuthTypeAPIKey:
		if a.APIKey != nil {
			creds.ApiKey = a.APIKey.APIKey
		}
	case AuthTypeAWS:
		if a.AWS != nil {
			creds.AwsBedrock = &providers.AwsBedrock{
				Region:       a.AWS.Region,
				AccessKey:    a.AWS.AccessKeyID,
				SecretKey:    a.AWS.SecretAccessKey,
				SessionToken: a.AWS.SessionToken,
				UseRole:      a.AWS.UseRole,
				RoleARN:      a.AWS.Role,
			}
		}
	case AuthTypeAzure:
		if a.Azure != nil {
			mode, _ := a.Azure.CredentialMode()
			creds.ApiKey = a.Azure.APIKey
			creds.Azure = &providers.Azure{
				Endpoint:     a.Azure.Endpoint,
				ApiVersion:   a.Azure.Version,
				AuthMode:     providers.AzureAuthMode(mode),
				UseIdentity:  a.Azure.UseManagedIdentity,
				TenantID:     a.Azure.TenantID,
				ClientID:     a.Azure.ClientID,
				ClientSecret: a.Azure.ClientSecret,
			}
		}
	case AuthTypeOAuth2, AuthTypeGCPServiceAccount:
		// Deferred to B.7.
	}
	return creds
}

func (a *TargetAuth) Validate() error {
	for _, v := range a.secretValues() {
		if secret.IsMasked(v) {
			return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value",
				ErrInvalidRegistry)
		}
	}
	switch a.Type {
	case AuthTypeAPIKey:
		if a.APIKey == nil {
			return fmt.Errorf("%w: api_key payload required for type api_key", ErrInvalidRegistry)
		}
		if a.APIKey.APIKey == "" && (a.APIKey.HeaderName == "" || a.APIKey.HeaderValue == "") &&
			(a.APIKey.ParamName == "" || a.APIKey.ParamValue == "") {
			return fmt.Errorf("%w: api_key requires api_key, header pair, or param pair", ErrInvalidRegistry)
		}
	case AuthTypeAzure:
		if a.Azure == nil {
			return fmt.Errorf("%w: azure payload required for type azure", ErrInvalidRegistry)
		}
		if err := a.Azure.Validate(); err != nil {
			return err
		}
	case AuthTypeAWS:
		if a.AWS == nil {
			return fmt.Errorf("%w: aws payload required for type aws", ErrInvalidRegistry)
		}
	case AuthTypeOAuth2:
		if a.OAuth == nil {
			return fmt.Errorf("%w: oauth configuration required for type oauth2", ErrInvalidRegistry)
		}
		if a.OAuth.TokenURL == "" {
			return fmt.Errorf("%w: oauth.token_url is required", ErrInvalidRegistry)
		}
		if a.OAuth.GrantType == "" {
			return fmt.Errorf("%w: oauth.grant_type is required", ErrInvalidRegistry)
		}
	case AuthTypeGCPServiceAccount:
		if a.GCPServiceAccount == nil || *a.GCPServiceAccount == "" {
			return fmt.Errorf("%w: gcp_service_account payload required", ErrInvalidRegistry)
		}
	default:
		return fmt.Errorf("%w: unknown auth type %q", ErrInvalidRegistry, a.Type)
	}
	return nil
}

func (a *AzureAuth) Validate() error {
	_, err := a.CredentialMode()
	return err
}

func (a *AzureAuth) CredentialMode() (AzureCredentialMode, error) {
	if strings.TrimSpace(a.Endpoint) == "" {
		return "", fmt.Errorf("%w: azure.endpoint is required", ErrInvalidRegistry)
	}

	apiKeyMode := strings.TrimSpace(a.APIKey) != ""
	servicePrincipalFields := 0
	if strings.TrimSpace(a.ClientID) != "" {
		servicePrincipalFields++
	}
	if strings.TrimSpace(a.ClientSecret) != "" {
		servicePrincipalFields++
	}
	if strings.TrimSpace(a.TenantID) != "" {
		servicePrincipalFields++
	}
	if servicePrincipalFields > 0 && servicePrincipalFields < 3 {
		return "", fmt.Errorf("%w: azure service principal requires client_id, client_secret, and tenant_id", ErrInvalidRegistry)
	}

	modeCount := 0
	if apiKeyMode {
		modeCount++
	}
	if servicePrincipalFields == 3 {
		modeCount++
	}
	if a.UseManagedIdentity {
		modeCount++
	}

	if modeCount == 0 {
		return "", fmt.Errorf("%w: azure requires exactly one auth mode: api_key, service principal, or use_managed_identity", ErrInvalidRegistry)
	}
	if modeCount > 1 {
		return "", fmt.Errorf("%w: azure auth modes are mutually exclusive", ErrInvalidRegistry)
	}
	if apiKeyMode {
		return AzureCredentialModeAPIKey, nil
	}
	if servicePrincipalFields == 3 {
		return AzureCredentialModeServicePrincipal, nil
	}
	return AzureCredentialModeDefaultAzureCredential, nil
}
