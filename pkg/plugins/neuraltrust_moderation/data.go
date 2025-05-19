package neuraltrust_moderation

type NeuralTrustModerationData struct {
	Blocked             bool                 `json:"blocked"`
	EmbeddingModeration *EmbeddingModeration `json:"embedding_moderation,omitempty"`
	KeyRegModeration    *KeyRegModeration    `json:"keyreg_moderation,omitempty"`
}

type EmbeddingScores struct {
	Scores map[string]float64 `json:"scores"`
}

type KeyRegReason struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
}

type EmbeddingModeration struct {
	Scores    *EmbeddingScores `json:"scores,omitempty"`
	Threshold float64          `json:"threshold"`
}

type KeyRegModeration struct {
	Reason              KeyRegReason `json:"reason"`
	SimilarityThreshold float64      `json:"similarity_threshold"`
}
