package token_rate_limiter

type TokenRateLimiterData struct {
	Stage           string `json:"stage"`
	CounterKey      string `json:"counter_key"`
	Provider        string `json:"provider,omitempty"`
	WindowUnit      string `json:"window_unit"`
	WindowMax       int    `json:"window_max"`
	TokensConsumed  int    `json:"tokens_consumed"`
	TokensActual    int    `json:"tokens_actual,omitempty"`
	TokensRemaining int    `json:"tokens_remaining"`
	LimitExceeded   bool   `json:"limit_exceeded"`
}
