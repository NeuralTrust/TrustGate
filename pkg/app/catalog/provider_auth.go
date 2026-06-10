package catalog

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers"

// AuthFieldType enumerates the credential field kinds the admin UI can render
// when building a provider connection form. It mirrors the compact vocabulary
// used by the policy catalog's settings schema.
type AuthFieldType string

const (
	AuthFieldTypeString  AuthFieldType = "string"
	AuthFieldTypeBoolean AuthFieldType = "boolean"
)

// AuthField describes a single credential input for a provider auth type.
type AuthField struct {
	Key         string        `json:"key"`
	Label       string        `json:"label"`
	Type        AuthFieldType `json:"type"`
	Description string        `json:"description,omitempty"`
	Required    bool          `json:"required,omitempty"`
	Secret      bool          `json:"secret,omitempty"`
}

// AuthTypeOption describes one authentication method a provider supports and the
// fields required to configure it. The Type matches the auth type accepted by
// the registry create/update API (api_key, azure, aws, gcp_service_account).
type AuthTypeOption struct {
	Type        string      `json:"type"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
	Fields      []AuthField `json:"fields"`
}

// Curated auth options shared across providers. They are hand-authored from the
// registry auth payloads (domain/registry.TargetAuth) so the catalog stays in
// sync with what the registry API actually accepts.
var (
	apiKeyAuthOption = AuthTypeOption{
		Type:  "api_key",
		Label: "API Key",
		Fields: []AuthField{
			{
				Key:         "api_key",
				Label:       "API Key",
				Type:        AuthFieldTypeString,
				Description: "Secret API key used to authenticate requests with the provider.",
				Required:    true,
				Secret:      true,
			},
		},
	}

	azureAuthOption = AuthTypeOption{
		Type:        "azure",
		Label:       "Azure OpenAI",
		Description: "Provide exactly one credential mode: API key, service principal (tenant_id + client_id + client_secret), or managed identity.",
		Fields: []AuthField{
			{
				Key:         "endpoint",
				Label:       "Endpoint",
				Type:        AuthFieldTypeString,
				Description: "Azure OpenAI resource endpoint URL.",
				Required:    true,
			},
			{
				Key:         "version",
				Label:       "API Version",
				Type:        AuthFieldTypeString,
				Description: "Azure OpenAI API version (e.g. 2024-02-01).",
			},
			{
				Key:         "api_key",
				Label:       "API Key",
				Type:        AuthFieldTypeString,
				Description: "Azure OpenAI api-key. Use for the API key credential mode.",
				Secret:      true,
			},
			{
				Key:         "tenant_id",
				Label:       "Tenant ID",
				Type:        AuthFieldTypeString,
				Description: "Service principal tenant ID.",
			},
			{
				Key:         "client_id",
				Label:       "Client ID",
				Type:        AuthFieldTypeString,
				Description: "Service principal client ID.",
			},
			{
				Key:         "client_secret",
				Label:       "Client Secret",
				Type:        AuthFieldTypeString,
				Description: "Service principal client secret.",
				Secret:      true,
			},
			{
				Key:         "use_managed_identity",
				Label:       "Use Managed Identity",
				Type:        AuthFieldTypeBoolean,
				Description: "Authenticate using the default Azure managed identity.",
			},
		},
	}

	awsAuthOption = AuthTypeOption{
		Type:        "aws",
		Label:       "AWS",
		Description: "AWS credentials used to sign Bedrock requests.",
		Fields: []AuthField{
			{
				Key:         "region",
				Label:       "Region",
				Type:        AuthFieldTypeString,
				Description: "AWS region hosting the Bedrock models.",
				Required:    true,
			},
			{
				Key:         "access_key_id",
				Label:       "Access Key ID",
				Type:        AuthFieldTypeString,
				Description: "AWS access key ID.",
				Required:    true,
			},
			{
				Key:         "secret_access_key",
				Label:       "Secret Access Key",
				Type:        AuthFieldTypeString,
				Description: "AWS secret access key.",
				Required:    true,
				Secret:      true,
			},
			{
				Key:         "session_token",
				Label:       "Session Token",
				Type:        AuthFieldTypeString,
				Description: "Temporary session token for STS credentials.",
				Secret:      true,
			},
			{
				Key:         "role",
				Label:       "Role ARN",
				Type:        AuthFieldTypeString,
				Description: "IAM role ARN to assume.",
			},
			{
				Key:         "use_role",
				Label:       "Assume Role",
				Type:        AuthFieldTypeBoolean,
				Description: "Assume the configured IAM role instead of using static keys.",
			},
		},
	}

	gcpServiceAccountAuthOption = AuthTypeOption{
		Type:  "gcp_service_account",
		Label: "GCP Service Account",
		Fields: []AuthField{
			{
				Key:         "gcp_service_account",
				Label:       "Service Account JSON",
				Type:        AuthFieldTypeString,
				Description: "GCP service account credentials JSON.",
				Required:    true,
				Secret:      true,
			},
		},
	}
)

// providerAuthCatalog maps each provider code to the authentication methods it
// supports. Only methods that the registry can actually use at runtime are
// advertised, so the catalog never surfaces an unsupported auth type.
var providerAuthCatalog = map[string][]AuthTypeOption{
	providers.ProviderOpenAI:           {apiKeyAuthOption},
	providers.ProviderOpenAICompatible: {apiKeyAuthOption},
	providers.ProviderGoogle:           {apiKeyAuthOption},
	providers.ProviderVertex:           {gcpServiceAccountAuthOption},
	providers.ProviderAnthropic:        {apiKeyAuthOption},
	providers.ProviderBedrock:          {awsAuthOption},
	providers.ProviderAzure:            {azureAuthOption},
	providers.ProviderMistral:          {apiKeyAuthOption},
	providers.ProviderGroq:             {apiKeyAuthOption},
}

// ProviderAuthOptions returns the supported authentication methods for a
// provider code. It returns an empty (non-nil) slice for unknown providers so
// the API always emits a JSON array.
func ProviderAuthOptions(code string) []AuthTypeOption {
	if opts, ok := providerAuthCatalog[code]; ok {
		return opts
	}
	return []AuthTypeOption{}
}
