package token_rate_limiter

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type TokenRateLimiterData struct {
	metric_events.PluginDataEvent
	Token         string `json:"key"`
	LimitExceeded bool   `json:"limit_exceeded"`
}
