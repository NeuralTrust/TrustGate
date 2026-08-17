// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"context"
	"errors"
	"time"
)

var ErrConnectRateLimitUnavailable = errors.New("connect rate limit unavailable")

type ConnectRateLimitUnavailable struct {
	cause error
}

func NewConnectRateLimitUnavailable(cause error) *ConnectRateLimitUnavailable {
	return &ConnectRateLimitUnavailable{cause: cause}
}

func (e *ConnectRateLimitUnavailable) Error() string {
	return ErrConnectRateLimitUnavailable.Error()
}

func (e *ConnectRateLimitUnavailable) Unwrap() error {
	return e.cause
}

func (e *ConnectRateLimitUnavailable) Is(target error) bool {
	return target == ErrConnectRateLimitUnavailable
}

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

type noopConnectAttemptLimiter struct{}

func NewNoopConnectAttemptLimiter() ConnectAttemptLimiter {
	return noopConnectAttemptLimiter{}
}

func (noopConnectAttemptLimiter) Check(context.Context, ConnectAttemptScope, string) error {
	return nil
}
