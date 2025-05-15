package toxicity_openai

type ToxicityOpenaiData struct {
	Flagged           bool        `json:"flagged"`
	Response          interface{} `json:"response"`
	FlaggedCategories []string    `json:"flagged_categories"`
}
