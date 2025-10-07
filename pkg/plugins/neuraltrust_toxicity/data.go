package neuraltrust_toxicity

type ToxicityData struct {
	ToxicityThreshold float64            `json:"toxicity_threshold"`
	Categories        map[string]float64 `json:"scores"`
}
