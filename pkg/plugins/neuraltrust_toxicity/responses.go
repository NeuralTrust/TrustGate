package neuraltrust_toxicity

type ToxicityResponse struct {
	Categories map[string]float64 `json:"categories"`
	Flagged    bool               `json:"flagged"`
}
