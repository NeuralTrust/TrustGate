package neuraltrust_toxicity

type ToxicityData struct {
	ToxicityThreshold float64 `json:"toxicity_threshold"`
	Scores            *Scores `json:"scores"`
}

type Scores struct {
	Toxicity float64 `json:"toxicity"`
}
