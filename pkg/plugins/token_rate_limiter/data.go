package token_rate_limiter

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type TokenRateLimiterData struct {
	metrics.PluginDataEvent
	Token         string `json:"key"`
	LimitExceeded bool   `json:"limit_exceeded"`
}
