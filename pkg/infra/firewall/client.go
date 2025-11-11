package firewall

import (
	"context"
)

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=firewall_client_mock.go --case=underscore --with-expecter
type Client interface {
	DetectJailbreak(ctx context.Context, content Content, credentials Credentials) ([]JailbreakResponse, error)
	DetectToxicity(ctx context.Context, content Content, credentials Credentials) ([]ToxicityResponse, error)
}

type Credentials struct {
	NeuralTrustCredentials NeuralTrustCredentials
	OpenAICredentials      OpenAICredentials
}

type NeuralTrustCredentials struct {
	BaseURL string
	Token   string
}

type OpenAICredentials struct {
	APIKey string
}

type JailbreakResponse struct {
	Scores JailbreakScores `json:"category_scores"`
}

type JailbreakScores struct {
	MaliciousPrompt float64 `json:"malicious_prompt"`
}

type ToxicityResponse struct {
	Categories     map[string]float64 `json:"categories,omitempty"`
	CategoryScores map[string]float64 `json:"category_scores,omitempty"`
	Scores         map[string]float64 `json:"scores,omitempty"`
}
