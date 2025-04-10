package prompt_moderation

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type PromptModerationData struct {
	metrics.PluginDataEvent
	Blocked             bool             `json:"blocked"`
	Reason              ModerationReason `json:"reason"`
	Keywords            []string         `json:"keywords"`
	Regex               []string         `json:"regex"`
	SimilarityThreshold float64          `json:"similarity_threshold"`
}

type ModerationReason struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
}
