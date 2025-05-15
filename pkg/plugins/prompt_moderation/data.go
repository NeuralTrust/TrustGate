package prompt_moderation

type PromptModerationData struct {
	Blocked             bool              `json:"blocked"`
	Reason              *ModerationReason `json:"reason,omitempty"`
	SimilarityThreshold float64           `json:"similarity_threshold"`
}

type ModerationReason struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Match   string `json:"match"`
}
