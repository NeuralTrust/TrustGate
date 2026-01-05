package toxicity_openai

type ToxicityOpenaiData struct {
	Model       string `json:"model"`
	InputLength int    `json:"input_length"`
	InputCount  int    `json:"input_count"`

	Scores    *ToxicityScores `json:"scores,omitempty"`
	Blocked   bool            `json:"blocked"`
	Violation *ViolationInfo  `json:"violation,omitempty"`

	DetectionLatencyMs int64 `json:"detection_latency_ms"`
}

type ToxicityScores struct {
	CategoryScores   map[string]float64 `json:"category_scores"`
	FlaggedByOpenAI  bool               `json:"flagged_by_openai"`
	MaxScore         float64            `json:"max_score"`
	MaxScoreCategory string             `json:"max_score_category"`
}

type ViolationInfo struct {
	FlaggedCategories []FlaggedCategory `json:"flagged_categories"`
	Message           string            `json:"message"`
}

type FlaggedCategory struct {
	Category  string  `json:"category"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold"`
}
