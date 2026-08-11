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

package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

const (
	ReasonBurst = "burst"
	ReasonQuota = "quota"
)

// ErrUnavailable is retained for transport mapping (HTTP 503 / JSON-RPC -32005).
// TrustGate Check fails open on entitlement load errors (including missing gateways);
// callers that still return this error map it to 503.
var ErrUnavailable = errors.New("rate limit entitlements unavailable")

// ErrUnmetered means the gateway has no stamped plan caps. Hot-path Check skips commercial rate limiting (OSS / self-hosted).
var ErrUnmetered = errors.New("rate limit entitlements unmetered")

// Exceeded is returned when a plan limit is hit (HTTP 429 / JSON-RPC -32004).
type Exceeded struct {
	Reason     string
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

func (e *Exceeded) Error() string {
	return fmt.Sprintf("rate limit exceeded: %s", e.Reason)
}

func (e *Exceeded) Headers() map[string][]string {
	return map[string][]string{
		"Retry-After":           {strconv.Itoa(RetryAfterSeconds(e.RetryAfter))},
		"X-RateLimit-Limit":     {strconv.Itoa(e.Limit)},
		"X-RateLimit-Remaining": {strconv.Itoa(e.Remaining)},
		"X-RateLimit-Reason":    {e.Reason},
	}
}

func (e *Exceeded) Body() []byte {
	retryAfter := RetryAfterSeconds(e.RetryAfter)
	payload := map[string]any{
		"error":               "rate limit exceeded",
		"message":             rateLimitClientMessage(e.Reason, retryAfter),
		"reason":              e.Reason,
		"limit":               e.Limit,
		"retry_after_seconds": retryAfter,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":"rate limit exceeded","reason":%q}`, e.Reason))
	}
	return raw
}

func rateLimitClientMessage(reason string, retryAfterSeconds int) string {
	switch reason {
	case ReasonBurst:
		return fmt.Sprintf("Request blocked: gateway burst rate limit exceeded. Retry after %ds.", retryAfterSeconds)
	case ReasonQuota:
		return fmt.Sprintf("Request blocked: monthly request quota exceeded. Retry after %ds.", retryAfterSeconds)
	default:
		return fmt.Sprintf("Request blocked: rate limit exceeded (%s). Retry after %ds.", reason, retryAfterSeconds)
	}
}

//go:generate mockery --name=Counter --dir=. --output=./mocks --filename=counter_mock.go --case=underscore --with-expecter
type Counter interface {
	IncrBurst(ctx context.Context, gatewayID ids.GatewayID) (count int64, ttl time.Duration, err error)
	IncrQuota(ctx context.Context, gatewayID ids.GatewayID, month string) (count int64, err error)
}

//go:generate mockery --name=GatewayTierLoader --dir=. --output=./mocks --filename=gateway_tier_loader_mock.go --case=underscore --with-expecter
type GatewayTierLoader interface {
	Limits(ctx context.Context, gatewayID ids.GatewayID) (domain.Limits, error)
}

//go:generate mockery --name=Checker --dir=. --output=./mocks --filename=checker_mock.go --case=underscore --with-expecter
type Checker interface {
	Check(ctx context.Context, gatewayID ids.GatewayID) error
}

type noopChecker struct{}

func (noopChecker) Check(context.Context, ids.GatewayID) error { return nil }

func NewNoopChecker() Checker { return noopChecker{} }
