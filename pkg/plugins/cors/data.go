package cors

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type CorsData struct {
	metrics.PluginDataEvent

	Origin          string   `json:"origin"`
	Method          string   `json:"method"`
	Preflight       bool     `json:"preflight"`
	Allowed         bool     `json:"allowed"`
	RequestedMethod string   `json:"requested_method"`
	AllowedMethods  []string `json:"allowed_methods"`
}
