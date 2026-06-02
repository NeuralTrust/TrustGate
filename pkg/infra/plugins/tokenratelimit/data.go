package tokenratelimit

// TokenRateLimiterData is the per-invocation trace payload describing the token
// budget window and the tokens consumed/remaining at each stage.
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
