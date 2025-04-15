package toxicity_azure

type ToxicityAzureData struct {
	Endpoint    string     `json:"endpoint"`
	Flagged     bool       `json:"flagged"`
	ContentType string     `json:"content_type"`
	Scores      ScoresData `json:"scores"`
}

type ScoresData struct {
	Hate     float64 `json:"hate"`
	Violence float64 `json:"violence"`
}
