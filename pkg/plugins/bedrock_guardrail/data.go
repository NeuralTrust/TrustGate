package bedrock_guardrail

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type BedrockGuardrailData struct {
	metrics.PluginDataEvent

	GuardrailID string                  `json:"guardrail_id"`
	Version     string                  `json:"version"`
	Blocked     bool                    `json:"blocked"`
	Events      []BedrockGuardrailEvent `json:"events"`
}

type BedrockGuardrailEvent struct {
	Type   string `json:"type"`   // e.g. "topic_policy", "sensitive_information"
	Name   string `json:"name"`   // e.g. "violence", "SSN"
	Action string `json:"action"` // e.g. "BLOCKED", "REJECT"
}
