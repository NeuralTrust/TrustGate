package neuraltrust_moderation

type NeuralTrustModerationData struct {
	ModerationThreshold float64           `json:"moderation_threshold"`
	Blocked             bool              `json:"blocked"`
	Scores              *ModerationScores `json:"scores,omitempty"`
}

type ModerationScores struct {
	ModerationScores map[string]float64 `json:"moderation_scores"`
}