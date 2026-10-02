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
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const instrumentation = "trustgate/ratelimit"

// meterMetrics holds the instruments of the counter path. Any of them may be
// nil when the SDK refused to create it, and every method tolerates that: a
// missing metric must never take the rate limiter down with it.
type meterMetrics struct {
	failOpen     metric.Int64Counter
	syncDuration metric.Float64Histogram
	syncErrors   metric.Int64Counter
	dropped      metric.Int64Counter
	kicks        metric.Int64Counter
	tracer       trace.Tracer
}

func newMeterMetrics(logger *slog.Logger, tracked func() int64) *meterMetrics {
	meter := otel.Meter(instrumentation)
	mm := &meterMetrics{tracer: otel.Tracer(instrumentation)}
	var err error
	if mm.failOpen, err = meter.Int64Counter(
		"trustgate.ratelimit.fail_open",
		metric.WithDescription("requests allowed because rate-limit enforcement failed open"),
	); err != nil {
		logger.Warn("failed to create rate-limit fail-open counter", slog.String("error", err.Error()))
	}
	if mm.syncDuration, err = meter.Float64Histogram(
		"trustgate.ratelimit.sync.duration",
		metric.WithUnit("s"),
		metric.WithDescription("duration of one background sync of plan counters to Redis"),
	); err != nil {
		logger.Warn("failed to create rate-limit sync duration histogram", slog.String("error", err.Error()))
	}
	if mm.syncErrors, err = meter.Int64Counter(
		"trustgate.ratelimit.sync.errors",
		metric.WithDescription("failed background syncs of plan counters; requests keep being served from memory"),
	); err != nil {
		logger.Warn("failed to create rate-limit sync error counter", slog.String("error", err.Error()))
	}
	if mm.dropped, err = meter.Int64Counter(
		"trustgate.ratelimit.sync.dropped",
		metric.WithDescription("plan units dropped unsent: Redis stayed unreachable past the retention (reason retention) or the shutdown flush ran out of time (reason shutdown)"),
	); err != nil {
		logger.Warn("failed to create rate-limit dropped counter", slog.String("error", err.Error()))
	}
	if mm.kicks, err = meter.Int64Counter(
		"trustgate.ratelimit.sync.kicks",
		metric.WithDescription("early syncs requested because a tenant's unsynced usage reached a tenth of its cap"),
	); err != nil {
		logger.Warn("failed to create rate-limit kick counter", slog.String("error", err.Error()))
	}
	if tracked != nil {
		if _, err := meter.Int64ObservableGauge(
			"trustgate.ratelimit.tracked_tenants",
			metric.WithDescription("tenants with an in-memory plan counter on this pod"),
			metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
				o.Observe(tracked())
				return nil
			}),
		); err != nil {
			logger.Warn("failed to create rate-limit tracked tenants gauge", slog.String("error", err.Error()))
		}
	}
	return mm
}

func (mm *meterMetrics) recordFailOpen(ctx context.Context, reason string) {
	if mm.failOpen != nil {
		mm.failOpen.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	}
}

func (mm *meterMetrics) recordSync(ctx context.Context, seconds float64, failed bool) {
	if mm.syncDuration != nil {
		mm.syncDuration.Record(ctx, seconds)
	}
	if failed && mm.syncErrors != nil {
		mm.syncErrors.Add(ctx, 1)
	}
}

func (mm *meterMetrics) recordDropped(ctx context.Context, units int64, reason string) {
	if units > 0 && mm.dropped != nil {
		mm.dropped.Add(ctx, units, metric.WithAttributes(attribute.String("reason", reason)))
	}
}

func (mm *meterMetrics) recordKick(ctx context.Context) {
	if mm.kicks != nil {
		mm.kicks.Add(ctx, 1)
	}
}
