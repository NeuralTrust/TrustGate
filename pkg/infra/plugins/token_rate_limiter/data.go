package token_rate_limiter

type TokenRateLimiterData struct {
	Stage           string `json:"stage"`
	BucketKey       string `json:"bucket_key"`
	Provider        string `json:"provider,omitempty"`
	BucketSize      int    `json:"bucket_size"`
	TokensPerMinute int    `json:"tokens_per_minute"`
	TokensReserved  int    `json:"tokens_reserved"`
	TokensActual    int    `json:"tokens_actual,omitempty"`
	Delta           int    `json:"delta,omitempty"`
	TokensRemaining int    `json:"tokens_remaining"`
	TokensConsumed  int    `json:"tokens_consumed"`
	LimitExceeded   bool   `json:"limit_exceeded"`
}
