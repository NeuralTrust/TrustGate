package ratelimit

// RateLimiterData is the per-invocation trace payload describing the evaluated
// rate-limit window and whether it was exceeded.
type RateLimiterData struct {
	RateLimitExceeded bool   `json:"rate_limit_exceeded"`
	ExceededType      string `json:"exceeded_type,omitempty"`
	RetryAfter        string `json:"retry_after,omitempty"`
	CurrentCount      int64  `json:"current_count"`
	Limit             int    `json:"limit"`
	Window            string `json:"window,omitempty"`
}
