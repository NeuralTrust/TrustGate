package cors

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type CorsData struct {
	metric_events.PluginDataEvent

	Origin          string   `json:"origin"`
	Method          string   `json:"method"`
	Preflight       bool     `json:"preflight"`
	Allowed         bool     `json:"allowed"`
	RequestedMethod string   `json:"requested_method"`
	AllowedMethods  []string `json:"allowed_methods"`
}
