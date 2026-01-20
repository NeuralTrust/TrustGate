package neuraltrust_moderation

type NeuralTrustModerationData struct {
	MappingField string `json:"mapping_field,omitempty"`
	InputLength  int    `json:"input_length"`
	Blocked      bool   `json:"blocked"`

	KeyRegModeration  *KeyRegModeration  `json:"keyreg_moderation,omitempty"`
	LLMModeration     *LLMModeration     `json:"llm_moderation,omitempty"`
	NTTopicModeration *NTTopicModeration `json:"nt_topic_moderation,omitempty"`
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

type NTTopicModeration struct {
	Blocked            bool                        `json:"blocked"`
	TopicScores        map[string]NTTopicScore     `json:"topic_scores,omitempty"`
	BlockedTopics      []string                    `json:"blocked_topics,omitempty"`
	Warnings           []string                    `json:"warnings,omitempty"`
	DetectionLatencyMs int64                       `json:"detection_latency_ms"`
}

type NTTopicScore struct {
	Topic       string  `json:"topic"`
	Probability float64 `json:"probability"`
	Blocked     bool    `json:"blocked"`
}
