package bedrock_guardrail

type BedrockGuardrailData struct {
	GuardrailID string                 `json:"guardrail_id"`
	Version     string                 `json:"version"`
	Blocked     bool                   `json:"blocked"`
	Event       *BedrockGuardrailEvent `json:"events,omitempty"`
}

type BedrockGuardrailEvent struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Action string `json:"action"`
}
