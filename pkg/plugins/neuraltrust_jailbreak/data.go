package neuraltrust_jailbreak

type NeuralTrustJailbreakData struct {
	JailbreakThreshold float64          `json:"jailbreak_threshold"`
	Scores             *JailbreakScores `json:"scores,omitempty"`
}

type JailbreakScores struct {
	Jailbreak float64 `json:"jailbreak"`
}
