package neuraltrust_jailbreak

type NeuralTrustJailbreakData struct {
	Provider           string  `json:"provider"`
	JailbreakThreshold float64 `json:"jailbreak_threshold"`
	MappingField       string  `json:"mapping_field,omitempty"`

	InputLength int `json:"input_length"`

	Scores    *JailbreakScores `json:"scores,omitempty"`
	Blocked   bool             `json:"blocked"`
	Violation *ViolationInfo   `json:"violation,omitempty"`

	DetectionLatencyMs int64 `json:"detection_latency_ms"`
}

type JailbreakScores struct {
	MaliciousPrompt float64 `json:"malicious_prompt"`
}

type ViolationInfo struct {
	Type      string  `json:"type"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold"`
	Message   string  `json:"message"`
}
