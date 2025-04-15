package token_rate_limiter

type TokenRateLimiterData struct {
	Tokens        int  `json:"tokens"`
	LimitExceeded bool `json:"limit_exceeded"`
}
