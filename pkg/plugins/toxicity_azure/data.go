package toxicity_azure

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type ToxicityAzureData struct {
	metrics.PluginDataEvent
	Endpoint    string     `json:"endpoint"`
	Flagged     bool       `json:"flagged"`
	ContentType string     `json:"content_type"`
	Scores      ScoresData `json:"scores"`
}

type ScoresData struct {
	Hate     float64 `json:"hate"`
	Violence float64 `json:"violence"`
}
