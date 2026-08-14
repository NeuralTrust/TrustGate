package oauth

import (
	"context"
	"time"
)

type ConnectAttemptScope uint8

const (
	ConnectAttemptScopeSource ConnectAttemptScope = iota + 1
	ConnectAttemptScopeConsumer
)

type ConnectRateLimitExceeded struct {
	RetryAfter time.Duration
}

func (e *ConnectRateLimitExceeded) Error() string {
	return "connect rate limit exceeded"
}

//go:generate mockery --name=ConnectAttemptLimiter --dir=. --output=./mocks --filename=oauth_connect_attempt_limiter_mock.go --case=underscore --with-expecter
type ConnectAttemptLimiter interface {
	Check(ctx context.Context, scope ConnectAttemptScope, subject string) error
}
