package neuraltrust_guardrail

type NeuralTrustGuardrailData struct {
	JailbreakThreshold float64          `json:"jailbreak_threshold"`
	Scores             *GuardrailScores `json:"scores,omitempty"`
}

type GuardrailScores struct {
	Jailbreak float64 `json:"jailbreak"`
}
