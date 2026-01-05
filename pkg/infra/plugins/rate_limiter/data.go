package rate_limiter

type RateLimiterData struct {
	RateLimitExceeded bool   `json:"rate_limit_exceeded"`
	ExceededType      string `json:"exceeded_type"` // e.g. "per_ip", "per_user"
	RetryAfter        string `json:"retry_after"`   // in seconds
	CurrentCount      int64  `json:"current_count"`
	Limit             int    `json:"limit"`
	Window            string `json:"window"` // e.g. "1h", "5m"
}
