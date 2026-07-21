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
	"log/slog"
	"math"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type checker struct {
	tiers    GatewayTierLoader
	counter  Counter
	logger   *slog.Logger
	now      func() time.Time
	failOpen metric.Int64Counter
}

// NewChecker builds the plan rate limiter (fail-open on Redis errors).
func NewChecker(tiers GatewayTierLoader, counter Counter, logger *slog.Logger) Checker {
	if logger == nil {
		logger = slog.Default()
	}
	failOpen, err := otel.Meter("trustgate/ratelimit").Int64Counter(
		"trustgate.ratelimit.fail_open",
		metric.WithDescription("requests allowed because rate-limit enforcement failed open"),
	)
	if err != nil {
		logger.Warn("failed to create rate-limit fail-open counter; fail-open will only be logged",
			slog.String("error", err.Error()))
		failOpen = nil
	}
	return &checker{tiers: tiers, counter: counter, logger: logger, now: time.Now, failOpen: failOpen}
}

func (c *checker) recordFailOpen(ctx context.Context, reason string) {
	if c.failOpen == nil {
		return
	}
	c.failOpen.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

func (c *checker) Check(ctx context.Context, gatewayID ids.GatewayID) error {
	limits, err := c.tiers.Limits(ctx, gatewayID)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) || errors.Is(err, ErrUnavailable) {
			return ErrUnavailable
		}
		c.logger.Warn("rate limit: failed to load entitlements; fail-open",
			slog.String("gateway_id", gatewayID.String()),
			slog.Any("error", err))
		c.recordFailOpen(ctx, "tier_load")
		return nil
	}

	burstCount, burstTTL, err := c.counter.IncrBurst(ctx, gatewayID)
	if err != nil {
		c.logger.Warn("rate limit: burst incr failed; fail-open",
			slog.String("gateway_id", gatewayID.String()),
			slog.Any("error", err))
		c.recordFailOpen(ctx, "burst_incr")
		return nil
	}
	if int(burstCount) > limits.BurstPerMin {
		retry := burstTTL
		if retry <= 0 {
			retry = time.Second
		}
		return &Exceeded{
			Reason:     ReasonBurst,
			Limit:      limits.BurstPerMin,
			Remaining:  0,
			RetryAfter: retry,
		}
	}

	if !limits.HasMonthlyQuota() {
		return nil
	}

	month := c.now().UTC().Format("2006-01")
	quotaCount, err := c.counter.IncrQuota(ctx, gatewayID, month)
	if err != nil {
		c.logger.Warn("rate limit: quota incr failed; fail-open",
			slog.String("gateway_id", gatewayID.String()),
			slog.Any("error", err))
		c.recordFailOpen(ctx, "quota_incr")
		return nil
	}
	if int(quotaCount) > limits.QuotaPerMonth {
		return &Exceeded{
			Reason:     ReasonQuota,
			Limit:      limits.QuotaPerMonth,
			Remaining:  0,
			RetryAfter: timeUntilNextUTCMonth(c.now()),
		}
	}
	return nil
}

func timeUntilNextUTCMonth(now time.Time) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	d := next.Sub(now)
	if d < time.Second {
		return time.Second
	}
	return d
}

// RetryAfterSeconds rounds a retry duration up to whole seconds.
func RetryAfterSeconds(d time.Duration) int {
	sec := int(math.Ceil(d.Seconds()))
	if sec < 1 {
		return 1
	}
	return sec
}
