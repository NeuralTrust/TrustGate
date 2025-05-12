package neuraltrust_guardrail

type NeuralTrustGuardrailData struct {
	ToxicityThreshold   float64         `json:"toxicity_threshold"`
	ModerationThreshold float64         `json:"moderation_threshold"`
	JailbreakThreshold  float64         `json:"jailbreak_threshold"`
	Blocked             bool            `json:"blocked"`
	Scores              GuardrailScores `json:"scores"`
}

type GuardrailScores struct {
	Toxicity        float64 `json:"toxicity"`
	Jailbreak       float64 `json:"jailbreak"`
	Moderation      float64 `json:"moderation"`
	ModerationMatch string  `json:"moderation_match"`
}
