package toxicity_openai

type ToxicityOpenaiData struct {
	Flagged  bool        `json:"flagged"`
	Response interface{} `json:"response"`
}
