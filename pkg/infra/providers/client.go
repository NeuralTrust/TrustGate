package providers

import (
	"context"
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
	ApiKey     string      `json:"api_key"`
	AwsBedrock *AwsBedrock `json:"aws,omitempty"`
	Azure      *Azure      `json:"azure,omitempty"`
}

type AwsBedrock struct {
	Region       string `json:"region"`
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token"`
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
	Ask(ctx context.Context, config *Config, prompt string) (*CompletionResponse, error)
	CompletionsStream(ctx context.Context, config *Config, streamChan chan []byte, reqBody []byte) error
	Completions(
		ctx context.Context,
		config *Config,
		reqBody []byte,
	) ([]byte, error)
}

func IsAllowedModel(model string, allowed []string) bool {
	for _, m := range allowed {
		if m == model {
			return true
		}
	}
	return false
}
