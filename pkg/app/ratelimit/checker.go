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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

const (
	ReasonBurst = "burst"
	ReasonQuota = "quota"
)

// ErrUnavailable means the gateway has no usable tier (HTTP 503 / JSON-RPC -32005).
var ErrUnavailable = errors.New("rate limit entitlements unavailable")

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
	return []byte(fmt.Sprintf(`{"error":"rate limit exceeded","reason":%q}`, e.Reason))
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
