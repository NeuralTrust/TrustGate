package data_masking

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type DataMaskingData struct {
	metric_events.PluginDataEvent

	Masked bool           `json:"masked"`
	Events []MaskingEvent `json:"events"`
}

type MaskingEvent struct {
	Entity        string `json:"entity"`
	OriginalValue string `json:"original_value"`
	MaskedWith    string `json:"masked_with"`
}
