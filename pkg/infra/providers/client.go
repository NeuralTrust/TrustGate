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

package providers

import (
	"context"
	"iter"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// Provider name constants. Use these as keys for HTTPClientPool.Get() and
// anywhere a provider needs to be identified by name. They alias the domain
// provider source of truth.
const (
	ProviderOpenAI           = provider.OpenAI
	ProviderOpenAICompatible = provider.OpenAICompatible
	ProviderGoogle           = provider.Google
	ProviderVertex           = provider.Vertex
	ProviderAnthropic        = provider.Anthropic
	ProviderBedrock          = provider.Bedrock
	ProviderAzure            = provider.Azure
	ProviderMistral          = provider.Mistral
	ProviderGroq             = provider.Groq
	ProviderDeepSeek         = provider.DeepSeek
	ProviderCohere           = provider.Cohere
)

type Config struct {
	Credentials   Credentials    `json:"credentials"`
	AllowedModels []string       `json:"allowed_models"`
	DefaultModel  string         `json:"default_model"`
	Model         string         `json:"model"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	Temperature   float64        `json:"temperature,omitempty"`
	SystemPrompt  string         `json:"system_prompt,omitempty"`
	Instructions  []string       `json:"instructions,omitempty"`
	Options       map[string]any `json:"options,omitempty"`
}

type Credentials struct {
	ApiKey     string      `json:"api_key"` // #nosec G117 -- DTO field for provider API key configuration
	AwsBedrock *AwsBedrock `json:"aws,omitempty"`
	Azure      *Azure      `json:"azure,omitempty"`
}

type AwsBedrock struct {
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`    // #nosec G117 -- DTO field for AWS access key configuration
	SecretKey    string `json:"secret_key"`    // #nosec G117 -- DTO field for AWS secret key configuration
	SessionToken string `json:"session_token"` // #nosec G117 -- DTO field for AWS session token configuration
	UseRole      bool   `json:"use_role"`
	RoleARN      string `json:"role_arn"`
}

type AzureAuthMode string

const (
	AzureAuthModeAPIKey                 AzureAuthMode = "api_key"
	AzureAuthModeServicePrincipal       AzureAuthMode = "service_principal"
	AzureAuthModeDefaultAzureCredential AzureAuthMode = "default_azure_credential" // #nosec G101 -- auth mode identifier, not a credential value
)

type Azure struct {
	Endpoint     string        `json:"endpoint"`
	ApiVersion   string        `json:"api_version"`
	AuthMode     AzureAuthMode `json:"auth_mode"`
	UseIdentity  bool          `json:"use_identity"`
	TenantID     string        `json:"tenant_id"`
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret"` // #nosec G117 -- Azure client secret credential
}

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=client_mock.go --case=underscore --with-expecter
type Client interface {
	Completions(
		ctx context.Context,
		config *Config,
		reqBody []byte,
	) ([]byte, error)
	// CompletionsStream performs the streaming request. The outer error carries
	// pre-stream failures (e.g. a registry.BackendError on a non-2xx response, for
	// verbatim passthrough). The returned sequence yields raw SSE lines and
	// surfaces mid-stream read errors as the second value.
	CompletionsStream(
		ctx context.Context,
		config *Config,
		reqBody []byte,
	) (iter.Seq2[[]byte, error], error)
}

// EmbeddingsClient performs non-streaming embedding requests.
type EmbeddingsClient interface {
	Embeddings(ctx context.Context, config *Config, reqBody []byte) ([]byte, error)
}

// RerankClient performs non-streaming rerank requests.
type RerankClient interface {
	Rerank(ctx context.Context, config *Config, reqBody []byte) ([]byte, error)
}
