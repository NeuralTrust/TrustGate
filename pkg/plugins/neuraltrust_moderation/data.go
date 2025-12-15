package neuraltrust_moderation

type NeuralTrustModerationData struct {
	MappingField string `json:"mapping_field,omitempty"`
	InputLength  int    `json:"input_length"`
	Blocked      bool   `json:"blocked"`

	EmbeddingModeration *EmbeddingModeration `json:"embedding_moderation,omitempty"`
	KeyRegModeration    *KeyRegModeration    `json:"keyreg_moderation,omitempty"`
	LLMModeration       *LLMModeration       `json:"llm_moderation,omitempty"`
}

type EmbeddingModeration struct {
	Provider           string           `json:"provider"`
	Model              string           `json:"model"`
	Threshold          float64          `json:"threshold"`
	Scores             *EmbeddingScores `json:"scores,omitempty"`
	Blocked            bool             `json:"blocked"`
	DetectionLatencyMs int64            `json:"detection_latency_ms"`
}

type EmbeddingScores struct {
	Scores     map[string]float64 `json:"scores"`
	MaxScore   float64            `json:"max_score"`
	MatchCount int                `json:"match_count"`
}

type KeyRegModeration struct {
	Blocked             bool         `json:"blocked"`
	SimilarityThreshold float64      `json:"similarity_threshold"`
	Reason              KeyRegReason `json:"reason,omitempty"`
	DetectionLatencyMs  int64        `json:"detection_latency_ms"`
}

type KeyRegReason struct {
	Type    string  `json:"type"`
	Pattern string  `json:"pattern"`
	Match   string  `json:"match"`
	Score   float64 `json:"score,omitempty"`
}

type LLMModeration struct {
	Blocked            bool   `json:"blocked"`
	Topic              string `json:"topic,omitempty"`
	InstructionMatch   string `json:"instruction_match,omitempty"`
	DetectionLatencyMs int64  `json:"detection_latency_ms"`
}
