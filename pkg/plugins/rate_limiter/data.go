package rate_limiter

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type RateLimiterData struct {
	metric_events.PluginDataEvent
	RateLimitExceeded bool   `json:"rate_limit_exceeded"`
	ExceededType      string `json:"exceeded_type"` // e.g. "per_ip", "per_user"
	RetryAfter        int    `json:"retry_after"`   // in seconds
	CurrentCount      int    `json:"current_count"`
	Limit             int    `json:"limit"`
	Window            string `json:"window"` // e.g. "1h", "5m"
}
