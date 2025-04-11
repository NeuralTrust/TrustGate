package request_size_limiter

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type RequestSizeLimiterData struct {
	metric_events.PluginDataEvent
	RequestSizeBytes   int64  `json:"request_size_bytes"`
	RequestSizeChars   int64  `json:"request_size_chars"`
	MaxSizeBytes       int64  `json:"max_size_bytes"`
	MaxCharsPerRequest int64  `json:"max_chars_per_request"`
	LimitExceeded      bool   `json:"limit_exceeded"`
	ExceededType       string `json:"exceeded_type"`
}
