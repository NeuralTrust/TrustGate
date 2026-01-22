package neuraltrust_toxicity

type ToxicityData struct {
	Provider     string `json:"provider"`
	MappingField string `json:"mapping_field,omitempty"`
	InputLength  int    `json:"input_length"`

	ToxicityThreshold float64 `json:"toxicity_threshold"`

	Scores    *ToxicityScores `json:"scores,omitempty"`
	Blocked   bool            `json:"blocked"`
	Violation *ViolationInfo  `json:"violation,omitempty"`

	DetectionLatencyMs int64 `json:"detection_latency_ms"`

	Mode string `json:"mode"`
}

type ToxicityScores struct {
	Categories       map[string]float64 `json:"categories"`
	MaxScore         float64            `json:"max_score"`
	MaxScoreCategory string             `json:"max_score_category"`
}

type ViolationInfo struct {
	Type      string  `json:"type"`
	Category  string  `json:"category"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold"`
	Message   string  `json:"message"`
}
