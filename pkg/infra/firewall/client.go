package firewall

import (
	"context"
)

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=firewall_client_mock.go --case=underscore --with-expecter
type Client interface {
	DetectJailbreak(ctx context.Context, content Content, credentials Credentials) ([]JailbreakResponse, error)
	DetectToxicity(ctx context.Context, content Content, credentials Credentials) ([]ToxicityResponse, error)
	DetectModeration(ctx context.Context, content ModerationContent, credentials Credentials) ([]ModerationResponse, error)
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

type ModerationContent struct {
	Input      []string           `json:"input"`
	Topics     []string           `json:"topics"`
	Thresholds map[string]float64 `json:"thresholds"`
}

type ModerationResponse struct {
	TopicScores   map[string]TopicScore `json:"topic_scores"`
	IsBlocked     bool                  `json:"is_blocked"`
	BlockedTopics []string              `json:"blocked_topics"`
	Warnings      []string              `json:"warnings"`
}

type TopicScore struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Blocked     bool    `json:"blocked"`
}
