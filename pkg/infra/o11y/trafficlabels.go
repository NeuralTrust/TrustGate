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

package o11y

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	labelIntakeMetric        = "agentgateway.traffic_labels.intake_total"
	labelEnqueueMetric       = "agentgateway.traffic_labels.enqueue_total"
	labelResultMetric        = "agentgateway.traffic_labels.result_total"
	labelCallMetric          = "agentgateway.traffic_labels.call.duration"
	labelStreamLengthMetric  = "agentgateway.traffic_labels.stream.length"
	labelStreamPendingMetric = "agentgateway.traffic_labels.stream.pending"

	streamStatsTimeout = 2 * time.Second
)

var outcomeKey = attribute.Key("outcome")

type StreamStats func(ctx context.Context) (length, pending int64, err error)

var _ trafficlabels.Recorder = (*TrafficLabelsMetrics)(nil)

type TrafficLabelsMetrics struct {
	enabled  bool
	intake   metric.Int64Counter
	enqueue  metric.Int64Counter
	results  metric.Int64Counter
	calls    metric.Float64Histogram
	outcomes map[string]metric.MeasurementOption
}

func NewTrafficLabelsMetrics(cfg *config.Config, _ *SDK, stats StreamStats) (*TrafficLabelsMetrics, error) {
	if cfg == nil || !cfg.Telemetry.OpsMetricsEnabled {
		return &TrafficLabelsMetrics{}, nil
	}
	return newTrafficLabelsMetrics(otel.Meter(instrumentationScope), stats)
}

func newTrafficLabelsMetrics(meter metric.Meter, stats StreamStats) (*TrafficLabelsMetrics, error) {
	m := &TrafficLabelsMetrics{enabled: true, outcomes: make(map[string]metric.MeasurementOption)}
	for _, outcome := range trafficlabels.Outcomes() {
		m.outcomes[outcome] = metric.WithAttributeSet(attribute.NewSet(outcomeKey.String(outcome)))
	}
	var err error
	if m.intake, err = meter.Int64Counter(labelIntakeMetric, metric.WithUnit("{request}"),
		metric.WithDescription("Requests offered to traffic labeling by the request path, by outcome.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", labelIntakeMetric, err)
	}
	if m.enqueue, err = meter.Int64Counter(labelEnqueueMetric, metric.WithUnit("{request}"),
		metric.WithDescription("Accepted requests and whether they reached the labeling queue.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", labelEnqueueMetric, err)
	}
	if m.results, err = meter.Int64Counter(labelResultMetric, metric.WithUnit("{request}"),
		metric.WithDescription("How each queued request ended.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", labelResultMetric, err)
	}
	if m.calls, err = meter.Float64Histogram(labelCallMetric, metric.WithUnit("s"),
		metric.WithDescription("Duration of each classifier LLM call, by outcome."),
		metric.WithExplicitBucketBoundaries(.05, .1, .25, .5, 1, 2.5, 5, 10, 30)); err != nil {
		return nil, fmt.Errorf("create %s: %w", labelCallMetric, err)
	}
	if stats != nil {
		if err := registerStreamGauges(meter, stats); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func registerStreamGauges(meter metric.Meter, stats StreamStats) error {
	length, err := meter.Int64ObservableGauge(labelStreamLengthMetric, metric.WithUnit("{entry}"),
		metric.WithDescription("Entries waiting in the traffic labels stream."))
	if err != nil {
		return fmt.Errorf("create %s: %w", labelStreamLengthMetric, err)
	}
	pending, err := meter.Int64ObservableGauge(labelStreamPendingMetric, metric.WithUnit("{entry}"),
		metric.WithDescription("Entries handed to a worker and not acknowledged yet."))
	if err != nil {
		return fmt.Errorf("create %s: %w", labelStreamPendingMetric, err)
	}
	_, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, streamStatsTimeout)
		defer cancel()
		l, p, err := stats(ctx)
		if err != nil {
			return nil
		}
		o.ObserveInt64(length, l)
		o.ObserveInt64(pending, p)
		return nil
	}, length, pending)
	if err != nil {
		return fmt.Errorf("register stream gauges: %w", err)
	}
	return nil
}

func (m *TrafficLabelsMetrics) Intake(outcome string) {
	if m == nil || !m.enabled {
		return
	}
	m.intake.Add(context.Background(), 1, m.attrs(outcome))
}

func (m *TrafficLabelsMetrics) Enqueue(outcome string) {
	if m == nil || !m.enabled {
		return
	}
	m.enqueue.Add(context.Background(), 1, m.attrs(outcome))
}

func (m *TrafficLabelsMetrics) Result(outcome string, n int) {
	if m == nil || !m.enabled || n <= 0 {
		return
	}
	m.results.Add(context.Background(), int64(n), m.attrs(outcome))
}

func (m *TrafficLabelsMetrics) Call(outcome string, d time.Duration) {
	if m == nil || !m.enabled {
		return
	}
	m.calls.Record(context.Background(), d.Seconds(), m.attrs(outcome))
}

func (m *TrafficLabelsMetrics) attrs(outcome string) metric.MeasurementOption {
	if opt, ok := m.outcomes[outcome]; ok {
		return opt
	}
	return metric.WithAttributes(outcomeKey.String(outcome))
}
