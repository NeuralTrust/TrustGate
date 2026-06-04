package providers

import (
	"context"
	"iter"
)

// Provider name constants. Use these as keys for HTTPClientPool.Get() and
// anywhere a provider needs to be identified by name.
const (
	ProviderOpenAI    = "openai"
	ProviderGoogle    = "google"
	ProviderVertex    = "vertex"
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"
	ProviderAzure     = "azure"
	ProviderMistral   = "mistral"
	ProviderGroq      = "groq"
)

// SupportedProviders returns every provider name the gateway can route to.
func SupportedProviders() []string {
	return []string{
		ProviderOpenAI,
		ProviderGoogle,
		ProviderVertex,
		ProviderAnthropic,
		ProviderBedrock,
		ProviderAzure,
		ProviderMistral,
		ProviderGroq,
	}
}

// IsValidProvider reports whether name is a supported provider.
func IsValidProvider(name string) bool {
	switch name {
	case ProviderOpenAI,
		ProviderGoogle,
		ProviderVertex,
		ProviderAnthropic,
		ProviderBedrock,
		ProviderAzure,
		ProviderMistral,
		ProviderGroq:
		return true
	default:
		return false
	}
}

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
