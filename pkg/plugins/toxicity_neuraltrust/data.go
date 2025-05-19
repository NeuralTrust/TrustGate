package toxicity_neuraltrust

type ToxicityData struct {
	Blocked           bool    `json:"blocked"`
	ToxicityThreshold float64 `json:"toxicity_threshold"`
	Scores            *Scores `json:"scores"`
}

type Scores struct {
	Toxicity float64 `json:"toxicity"`
}
