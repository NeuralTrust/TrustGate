package neuraltrust_guardrail

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type NeuralTrustGuardrailData struct {
	metric_events.PluginDataEvent
	ToxicityThreshold  float64         `json:"toxicity_threshold"`
	JailbreakThreshold float64         `json:"jailbreak_threshold"`
	Blocked            bool            `json:"blocked"`
	Scores             GuardrailScores `json:"scores"`
}

type GuardrailScores struct {
	Toxicity  float64 `json:"toxicity"`
	Jailbreak float64 `json:"jailbreak"`
}
