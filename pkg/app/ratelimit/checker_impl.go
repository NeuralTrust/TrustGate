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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type checker struct {
	tiers   GatewayTierLoader
	counter Counter
	logger  *slog.Logger
	now     func() time.Time
}

// NewChecker builds the plan rate limiter (fail-open on Redis errors).
func NewChecker(tiers GatewayTierLoader, counter Counter, logger *slog.Logger) Checker {
	if logger == nil {
		logger = slog.Default()
	}
	return &checker{tiers: tiers, counter: counter, logger: logger, now: time.Now}
}

func (c *checker) Check(ctx context.Context, gatewayID ids.GatewayID) error {
	tier, err := c.tiers.Tier(ctx, gatewayID)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			return ErrUnavailable
		}
		c.logger.Warn("rate limit: failed to load entitlements; fail-open",
			slog.String("gateway_id", gatewayID.String()),
			slog.Any("error", err))
		return nil
	}

	limits, ok := domain.LimitsFor(tier)
	if !ok {
		return ErrUnavailable
	}

	burstCount, burstTTL, err := c.counter.IncrBurst(ctx, gatewayID)
	if err != nil {
		c.logger.Warn("rate limit: burst incr failed; fail-open",
			slog.String("gateway_id", gatewayID.String()),
			slog.Any("error", err))
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
