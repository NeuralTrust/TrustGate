package providers

import (
	"context"
)

type Config struct {
	Credentials  Credentials `json:"credentials"`
	Model        string      `json:"model"`
	MaxTokens    int         `json:"max_tokens,omitempty"`
	Temperature  float64     `json:"temperature,omitempty"`
	SystemPrompt string      `json:"system_prompt,omitempty"`
	Instructions []string    `json:"instructions,omitempty"`
}

type Credentials struct {
	ApiKey string `json:"api_key"`
}

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=client_mock.go --case=underscore --with-expecter

type Client interface {
	Ask(ctx context.Context, config *Config, prompt string) (*CompletionResponse, error)
}
