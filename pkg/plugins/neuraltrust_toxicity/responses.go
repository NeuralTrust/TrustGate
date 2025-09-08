package neuraltrust_toxicity

type ToxicityResponse struct {
	Prompt  ToxicityPrompt `json:"categories"`
	Scores  ToxicityScores `json:"category_scores"`
	Flagged bool           `json:"flagged"`
}

type ToxicityPrompt struct {
	ToxicPrompt bool `json:"toxic_prompt"`
}

type ToxicityScores struct {
	ToxicPrompt float64 `json:"toxic_prompt"`
}
