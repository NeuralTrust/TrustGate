package response

import appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"

type TestConnectionResponse struct {
	OK         bool   `json:"ok"`
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMs  int64  `json:"latency_ms"`
	Message    string `json:"message,omitempty"`
}

func FromTestConnectionResult(r appregistry.TestConnectionResult) TestConnectionResponse {
	return TestConnectionResponse{
		OK:         r.OK,
		Stage:      r.Stage,
		Provider:   r.Provider,
		StatusCode: r.StatusCode,
		LatencyMs:  r.LatencyMs,
		Message:    r.Message,
	}
}
