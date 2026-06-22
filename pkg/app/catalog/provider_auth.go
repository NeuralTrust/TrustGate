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

package catalog

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers"

type AuthFieldType string

const (
	AuthFieldTypeString  AuthFieldType = "string"
	AuthFieldTypeBoolean AuthFieldType = "boolean"
)

type AuthField struct {
	Key         string        `json:"key"`
	Label       string        `json:"label"`
	Type        AuthFieldType `json:"type"`
	Description string        `json:"description,omitempty"`
	Required    bool          `json:"required,omitempty"`
	Secret      bool          `json:"secret,omitempty"`
	Default     any           `json:"default,omitempty"`
}

type AuthTypeOption struct {
	Type        string      `json:"type"`
	Variant     string      `json:"variant,omitempty"`
	Label       string      `json:"label"`
	Description string      `json:"description,omitempty"`
	Fields      []AuthField `json:"fields"`
}

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

	openAICompatibleAuthOption = AuthTypeOption{
		Type:        "api_key",
		Label:       "API Key",
		Description: "Authenticate with a bearer API key and/or a custom header pair.",
		Fields: []AuthField{
			{
				Key:         "api_key",
				Label:       "API Key",
				Type:        AuthFieldTypeString,
				Description: "Secret API key sent as a Bearer token (optional if using a custom header).",
				Secret:      true,
			},
			{
				Key:         "header_name",
				Label:       "Header Name",
				Type:        AuthFieldTypeString,
				Description: "Custom HTTP header name used to authenticate requests.",
			},
			{
				Key:         "header_value",
				Label:       "Header Value",
				Type:        AuthFieldTypeString,
				Description: "Value for the custom authentication header.",
				Secret:      true,
			},
		},
	}

	azureEndpointField = AuthField{
		Key:         "endpoint",
		Label:       "Endpoint",
		Type:        AuthFieldTypeString,
		Description: "Azure OpenAI resource endpoint URL.",
		Required:    true,
	}
	azureVersionField = AuthField{
		Key:         "version",
		Label:       "API Version",
		Type:        AuthFieldTypeString,
		Description: "Azure OpenAI API version (e.g. 2024-02-01).",
	}

	azureAuthOptions = []AuthTypeOption{
		{
			Type:    "azure",
			Variant: "api_key",
			Label:   "API Key",
			Fields: []AuthField{
				azureEndpointField,
				azureVersionField,
				{
					Key:      "api_key",
					Label:    "API Key",
					Type:     AuthFieldTypeString,
					Required: true,
					Secret:   true,
				},
			},
		},
		{
			Type:    "azure",
			Variant: "service_principal",
			Label:   "Service principal",
			Fields: []AuthField{
				azureEndpointField,
				{
					Key:      "tenant_id",
					Label:    "Tenant ID",
					Type:     AuthFieldTypeString,
					Required: true,
				},
				{
					Key:      "client_id",
					Label:    "Client ID",
					Type:     AuthFieldTypeString,
					Required: true,
				},
				{
					Key:      "client_secret",
					Label:    "Client Secret",
					Type:     AuthFieldTypeString,
					Required: true,
					Secret:   true,
				},
			},
		},
		{
			Type:    "azure",
			Variant: "managed_identity",
			Label:   "Managed identity",
			Fields: []AuthField{
				azureEndpointField,
				{
					Key:      "use_managed_identity",
					Label:    "Use Managed Identity",
					Type:     AuthFieldTypeBoolean,
					Required: true,
					Default:  true,
				},
			},
		},
	}

	awsRegionField = AuthField{
		Key:         "region",
		Label:       "Region",
		Type:        AuthFieldTypeString,
		Description: "AWS region hosting the Bedrock models.",
		Required:    true,
	}
	awsAccessKeyField = AuthField{
		Key:         "access_key_id",
		Label:       "Access Key ID",
		Type:        AuthFieldTypeString,
		Description: "AWS access key ID.",
		Required:    true,
	}
	awsSecretKeyField = AuthField{
		Key:         "secret_access_key",
		Label:       "Secret Access Key",
		Type:        AuthFieldTypeString,
		Description: "AWS secret access key.",
		Required:    true,
		Secret:      true,
	}

	awsAuthOptions = []AuthTypeOption{
		{
			Type:    "aws",
			Variant: "access_key",
			Label:   "Access key",
			Fields: []AuthField{
				awsRegionField,
				awsAccessKeyField,
				awsSecretKeyField,
				{
					Key:         "session_token",
					Label:       "Session Token",
					Type:        AuthFieldTypeString,
					Description: "Temporary session token for STS credentials.",
					Secret:      true,
				},
			},
		},
		{
			Type:    "aws",
			Variant: "assume_role",
			Label:   "Assume role",
			Fields: []AuthField{
				awsRegionField,
				awsAccessKeyField,
				awsSecretKeyField,
				{
					Key:         "role",
					Label:       "Role ARN",
					Type:        AuthFieldTypeString,
					Description: "IAM role ARN to assume.",
					Required:    true,
				},
				{
					Key:         "use_role",
					Label:       "Assume Role",
					Type:        AuthFieldTypeBoolean,
					Description: "Assume the configured IAM role using the base credentials above.",
					Required:    true,
					Default:     true,
				},
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

var providerAuthCatalog = map[string][]AuthTypeOption{
	providers.ProviderOpenAI:           {apiKeyAuthOption},
	providers.ProviderOpenAICompatible: {openAICompatibleAuthOption},
	providers.ProviderGoogle:           {apiKeyAuthOption},
	providers.ProviderVertex:           {gcpServiceAccountAuthOption},
	providers.ProviderAnthropic:        {apiKeyAuthOption},
	providers.ProviderBedrock:          awsAuthOptions,
	providers.ProviderAzure:            azureAuthOptions,
	providers.ProviderMistral:          {apiKeyAuthOption},
	providers.ProviderGroq:             {apiKeyAuthOption},
	providers.ProviderDeepSeek:         {apiKeyAuthOption},
}

func ProviderAuthOptions(code string) []AuthTypeOption {
	if opts, ok := providerAuthCatalog[code]; ok {
		return opts
	}
	return []AuthTypeOption{}
}
