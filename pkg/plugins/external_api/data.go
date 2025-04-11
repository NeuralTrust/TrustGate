package external_api

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type ExternalAPIData struct {
	metric_events.PluginDataEvent

	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	Response   string `json:"response"`
}
