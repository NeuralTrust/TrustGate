package bedrock_guardrail

type BedrockGuardrailData struct {
	GuardrailID string `json:"guardrail_id"`
	Version     string `json:"version"`
	Region      string `json:"region"`
	InputLength int    `json:"input_length"`

	Blocked   bool           `json:"blocked"`
	Violation *ViolationInfo `json:"violation,omitempty"`

	DetectionLatencyMs int64 `json:"detection_latency_ms"`
}

type ViolationInfo struct {
	PolicyType string `json:"policy_type"`
	Name       string `json:"name"`
	Action     string `json:"action"`
	Message    string `json:"message"`
}
