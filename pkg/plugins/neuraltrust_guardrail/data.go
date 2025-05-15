package neuraltrust_guardrail

type NeuralTrustGuardrailData struct {
	ToxicityThreshold   float64          `json:"toxicity_threshold"`
	ModerationThreshold float64          `json:"moderation_threshold"`
	JailbreakThreshold  float64          `json:"jailbreak_threshold"`
	Blocked             bool             `json:"blocked"`
	Scores              *GuardrailScores `json:"scores,omitempty"`
}

type GuardrailScores struct {
	Toxicity         float64            `json:"toxicity"`
	Jailbreak        float64            `json:"jailbreak"`
	ModerationScores map[string]float64 `json:"moderation_scores"`
}
