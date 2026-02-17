package providers

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

// Provider name constants. Use these as keys for HTTPClientPool.Get() and
// anywhere a provider needs to be identified by name.
const (
	ProviderOpenAI    = "openai"
	ProviderGoogle    = "google"
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"
	ProviderAzure     = "azure"
	ProviderMistral   = "mistral"
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

type Azure struct {
	Endpoint    string `json:"endpoint"`
	ApiVersion  string `json:"api_version"`
	UseIdentity bool   `json:"use_identity"`
}

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=client_mock.go --case=underscore --with-expecter

type Client interface {
	CompletionsStream(
		req *types.RequestContext,
		config *Config,
		reqBody []byte,
		streamChan chan []byte,
		breakChan chan struct{},
	) error
	Completions(
		ctx context.Context,
		config *Config,
		reqBody []byte,
	) ([]byte, error)
}
