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
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	ReasonBurst = "burst"
	ReasonQuota = "quota"
)

// ErrUnavailable means the gateway has no usable tier (map to HTTP 503 for the
// proxy path, or an internal JSON-RPC error for MCP).
var ErrUnavailable = errors.New("rate limit entitlements unavailable")

// Exceeded is returned when a plan limit is hit (map to HTTP 429 / JSON-RPC -32004).
type Exceeded struct {
	Reason     string
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

func (e *Exceeded) Error() string {
	return fmt.Sprintf("rate limit exceeded: %s", e.Reason)
}

// Headers renders the standard plan rate-limit response headers.
func (e *Exceeded) Headers() map[string][]string {
	return map[string][]string{
		"Retry-After":           {strconv.Itoa(RetryAfterSeconds(e.RetryAfter))},
		"X-RateLimit-Limit":     {strconv.Itoa(e.Limit)},
		"X-RateLimit-Remaining": {strconv.Itoa(e.Remaining)},
		"X-RateLimit-Reason":    {e.Reason},
	}
}

// Body renders the standard plan rate-limit JSON body.
func (e *Exceeded) Body() []byte {
	return []byte(fmt.Sprintf(`{"error":"rate limit exceeded","reason":%q}`, e.Reason))
}

// Counter increments Redis plan counters atomically (INCR).
//
//go:generate mockery --name=Counter --dir=. --output=./mocks --filename=counter_mock.go --case=underscore --with-expecter
type Counter interface {
	IncrBurst(ctx context.Context, gatewayID ids.GatewayID) (count int64, ttl time.Duration, err error)
	IncrQuota(ctx context.Context, gatewayID ids.GatewayID, month string) (count int64, err error)
}

// GatewayTierLoader loads the entitlements tier for a gateway.
//
//go:generate mockery --name=GatewayTierLoader --dir=. --output=./mocks --filename=gateway_tier_loader_mock.go --case=underscore --with-expecter
type GatewayTierLoader interface {
	Tier(ctx context.Context, gatewayID ids.GatewayID) (string, error)
}

// Checker enforces plan burst/quota after gateway resolve, before the request
// reaches the upstream (LLM provider or MCP tool).
//
//go:generate mockery --name=Checker --dir=. --output=./mocks --filename=checker_mock.go --case=underscore --with-expecter
type Checker interface {
	Check(ctx context.Context, gatewayID ids.GatewayID) error
}

type noopChecker struct{}

func (noopChecker) Check(context.Context, ids.GatewayID) error { return nil }

// NewNoopChecker returns a checker that always allows traffic (flag off).
func NewNoopChecker() Checker { return noopChecker{} }
