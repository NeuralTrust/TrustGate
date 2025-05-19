package neuraltrust_guardrail

type NeuralTrustGuardrailData struct {
	JailbreakThreshold float64          `json:"jailbreak_threshold"`
	Blocked            bool             `json:"blocked"`
	Scores             *GuardrailScores `json:"scores,omitempty"`
}

type GuardrailScores struct {
	Jailbreak float64 `json:"jailbreak"`
}
