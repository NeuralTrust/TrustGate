package neuraltrust_toxicity

type ToxicityDataV2 struct {
	ToxicityThreshold float64            `json:"toxicity_threshold"`
	Categories        map[string]float64 `json:"scores"`
}

// Legacy

type ToxicityData struct {
	ToxicityThreshold float64 `json:"toxicity_threshold"`
	Scores            *Scores `json:"scores"`
}

type Scores struct {
	Toxicity float64 `json:"toxicity"`
}
