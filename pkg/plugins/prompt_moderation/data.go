package prompt_moderation

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type PromptModerationData struct {
	metric_events.PluginDataEvent
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
