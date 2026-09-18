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
	"time"
)

// The MCP plane's floor: how much traffic one origin may send before it has
// proved anything.
//
// This is not the plan limit. Checker meters what a tenant bought — it is keyed
// by gateway, runs inside the RPC dispatcher, and therefore only ever sees
// requests that already resolved a consumer. Half the plane never gets that
// far: dynamic client registration, the token exchange, the authorize
// redirect and /whoami all answer before any credential is known, and metering
// anonymous abuse against a customer's monthly quota would turn a flood into
// their billing problem and their outage. So the two coexist: this one guards
// the database, Checker guards the plan.

// PlaneClass groups the plane's routes by what a request costs before it is
// authenticated.
type PlaneClass uint8

const (
	// PlaneClassDefault is read-mostly traffic: discovery documents, brand
	// assets, and the authenticated MCP surface (which the plan limit meters
	// again, per tenant, once the consumer is known).
	PlaneClassDefault PlaneClass = iota + 1
	// PlaneClassCredential is everything that mints, exchanges or verifies a
	// credential — it writes rows or answers "is this secret real", so it is
	// the half worth guessing at, and it gets the tighter window.
	PlaneClassCredential
)

// PlaneLimitExceeded is the refusal, carrying how long the bucket needs.
type PlaneLimitExceeded struct {
	RetryAfter time.Duration
}

func (e *PlaneLimitExceeded) Error() string {
	return "mcp plane rate limit exceeded"
}

// ErrPlaneLimiterUnavailable: the counter could not be reached. Callers fail
// open — a limiter that takes the plane down with it when Redis blinks is a
// worse outage than the one it prevents.
var ErrPlaneLimiterUnavailable = errors.New("ratelimit: mcp plane limiter unavailable")

// PlaneLimiter counts requests per origin, per class, in a fixed window.
//
// The subject is opaque to the limiter: the caller decides what an origin is
// (see ResolveConnectSource for the trusted-proxy rules) and the limiter only
// counts. It never sees an address in the clear — the key is an HMAC.
//
//go:generate mockery --name=PlaneLimiter --dir=. --output=./mocks --filename=ratelimit_plane_limiter_mock.go --case=underscore --with-expecter
type PlaneLimiter interface {
	Check(ctx context.Context, class PlaneClass, subject string) error
}

type noopPlaneLimiter struct{}

// NewNoopPlaneLimiter counts nothing: the configuration turned the floor off,
// or this build has no Redis to count in.
func NewNoopPlaneLimiter() PlaneLimiter { return noopPlaneLimiter{} }

func (noopPlaneLimiter) Check(context.Context, PlaneClass, string) error { return nil }
