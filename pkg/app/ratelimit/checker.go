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
	"log/slog"
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

// ErrUnmetered means the gateway is not metered: it has no tenant, or neither
// tenant caps nor a stamp. Hot-path Check skips plan rate limiting (OSS /
// self-hosted) and leaves no counter behind.
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
		return fmt.Sprintf("TrustGate blocked this request: gateway burst rate limit exceeded. Retry in %ds.", retryAfterSeconds)
	case ReasonQuota:
		return fmt.Sprintf("TrustGate blocked this request: monthly request quota exceeded. Retry in %ds.", retryAfterSeconds)
	default:
		return fmt.Sprintf("TrustGate blocked this request: rate limit exceeded (%s). Retry in %ds.", reason, retryAfterSeconds)
	}
}

// Resolved is what a gateway's plan resolves to: the subject its requests are
// counted under and the caps they are compared against.
//
// The subject is the tenant, so every gateway of a tenant adds to one counter
// and the plan cannot be multiplied by creating instances.
type Resolved struct {
	Subject string
	Limits  domain.Limits
}

// SyncBackend applies batched counter deltas to the shared store and returns the
// new totals. It is called only from the background sync loop, never from a
// request.
type SyncBackend interface {
	Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error)
}

//go:generate mockery --name=GatewayTierLoader --dir=. --output=./mocks --filename=gateway_tier_loader_mock.go --case=underscore --with-expecter
type GatewayTierLoader interface {
	// Resolve maps a gateway to its counting subject and caps. It returns
	// ErrUnmetered for a gateway that has no tenant, or neither tenant caps nor
	// a stamp: that is OSS / self-hosted traffic, which is not metered.
	Resolve(ctx context.Context, gatewayID ids.GatewayID) (Resolved, error)
}

//go:generate mockery --name=Checker --dir=. --output=./mocks --filename=checker_mock.go --case=underscore --with-expecter
type Checker interface {
	// Check charges one request against the gateway's plan, in memory: it never
	// waits on Redis.
	Check(ctx context.Context, gatewayID ids.GatewayID) error
}

type noopChecker struct{}

func (noopChecker) Check(context.Context, ids.GatewayID) error { return nil }

func NewNoopChecker() Checker { return noopChecker{} }

func loggerOrDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
