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

package secretref

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const (
	meterName = "trustgate/secretstore"

	fetchesMetric         = "trustgate.secretstore.fetches"
	fetchDurationMetric   = "trustgate.secretstore.fetch_duration"
	staleServedMetric     = "trustgate.secretstore.stale_served"
	forcedRefreshesMetric = "trustgate.secretstore.forced_refreshes"
	probesMetric          = "trustgate.secretstore.probes"

	resultOK = "ok"
)

// metrics labels every instrument with the store type and an outcome only:
// never a store name, a path, a field or a value.
type metrics struct {
	fetches         metric.Int64Counter
	fetchDuration   metric.Float64Histogram
	staleServes     metric.Int64Counter
	forcedRefreshes metric.Int64Counter
	probes          metric.Int64Counter
}

func newMetrics(meter metric.Meter, logger *slog.Logger) *metrics {
	fallback := noop.NewMeterProvider().Meter(meterName)
	counter := func(name, unit, description string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithUnit(unit), metric.WithDescription(description))
		if err != nil {
			logger.Warn("failed to create secret store metric", slog.String("metric", name), slog.String("error", err.Error()))
			c, _ = fallback.Int64Counter(name)
		}
		return c
	}
	duration, err := meter.Float64Histogram(fetchDurationMetric, metric.WithUnit("s"),
		metric.WithDescription("time to read one secret payload from a store, by store type"))
	if err != nil {
		logger.Warn("failed to create secret store metric", slog.String("metric", fetchDurationMetric), slog.String("error", err.Error()))
		duration, _ = fallback.Float64Histogram(fetchDurationMetric)
	}
	return &metrics{
		fetches: counter(fetchesMetric, "{fetch}",
			"secret payload reads, by store type and result (ok or the error class)"),
		fetchDuration: duration,
		staleServes: counter(staleServedMetric, "{resolution}",
			"references resolved with a value past its TTL because the store did not answer, by store type"),
		forcedRefreshes: counter(forcedRefreshesMetric, "{refresh}",
			"payloads re-read because an upstream rejected the credential, by whether the value changed"),
		probes: counter(probesMetric, "{probe}",
			"store credential probes, by store type and result (ok or the error class)"),
	}
}

func result(c secretstore.Class) string {
	if c == "" {
		return resultOK
	}
	return string(c)
}

func (m *metrics) fetched(ctx context.Context, t secretstore.Type, c secretstore.Class, took time.Duration) {
	typ := attribute.String("store_type", string(t))
	m.fetches.Add(ctx, 1, metric.WithAttributes(typ, attribute.String("result", result(c))))
	m.fetchDuration.Record(ctx, took.Seconds(), metric.WithAttributes(typ))
}

func (m *metrics) staleServed(ctx context.Context, t secretstore.Type) {
	m.staleServes.Add(ctx, 1, metric.WithAttributes(attribute.String("store_type", string(t))))
}

func (m *metrics) forcedRefresh(ctx context.Context, changed bool) {
	m.forcedRefreshes.Add(ctx, 1, metric.WithAttributes(attribute.Bool("changed", changed)))
}

func (m *metrics) probed(ctx context.Context, t secretstore.Type, c secretstore.Class) {
	m.probes.Add(ctx, 1, metric.WithAttributes(attribute.String("store_type", string(t)), attribute.String("result", result(c))))
}
