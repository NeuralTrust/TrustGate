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

	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	topicIntakeMetric        = "agentgateway.topic_classifier.intake_total"
	topicEnqueueMetric       = "agentgateway.topic_classifier.enqueue_total"
	topicResultMetric        = "agentgateway.topic_classifier.result_total"
	topicCallMetric          = "agentgateway.topic_classifier.call.duration"
	topicCallTextsMetric     = "agentgateway.topic_classifier.call.texts"
	topicStreamLengthMetric  = "agentgateway.topic_classifier.stream.length"
	topicStreamPendingMetric = "agentgateway.topic_classifier.stream.pending"

	streamStatsTimeout = 2 * time.Second
)

var outcomeKey = attribute.Key("outcome")

// StreamStats reports the classification queue length and how many entries
// were handed out but not acknowledged.
type StreamStats func(ctx context.Context) (length, pending int64, err error)

var _ topicclassifier.Recorder = (*TopicClassifierMetrics)(nil)

// TopicClassifierMetrics records the async topic classifier's operational
// counts. Outcome is the only label, so the series stay bounded whatever the
// number of gateways.
type TopicClassifierMetrics struct {
	enabled   bool
	intake    metric.Int64Counter
	enqueue   metric.Int64Counter
	results   metric.Int64Counter
	calls     metric.Float64Histogram
	callTexts metric.Int64Histogram
	// outcomes holds one prepared label set per outcome, so recording on the
	// request path does not build one per call.
	outcomes map[string]metric.MeasurementOption
}

// NewTopicClassifierMetrics creates the instruments. Like NewProvider it runs
// after SDK installed the global MeterProvider. When stats is set, the stream
// length and pending count are exported as gauges on every collection, so a
// backlog is visible even while no request is flowing.
func NewTopicClassifierMetrics(cfg *config.Config, _ *SDK, stats StreamStats) (*TopicClassifierMetrics, error) {
	if cfg == nil || !cfg.Telemetry.OpsMetricsEnabled {
		return &TopicClassifierMetrics{}, nil
	}
	return newTopicClassifierMetrics(otel.Meter(instrumentationScope), stats)
}

func newTopicClassifierMetrics(meter metric.Meter, stats StreamStats) (*TopicClassifierMetrics, error) {
	m := &TopicClassifierMetrics{enabled: true, outcomes: make(map[string]metric.MeasurementOption)}
	for _, outcome := range topicclassifier.Outcomes() {
		m.outcomes[outcome] = metric.WithAttributeSet(attribute.NewSet(outcomeKey.String(outcome)))
	}
	var err error
	if m.intake, err = meter.Int64Counter(topicIntakeMetric, metric.WithUnit("{request}"),
		metric.WithDescription("Requests offered to the topic classifier by the request path, by outcome.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", topicIntakeMetric, err)
	}
	if m.enqueue, err = meter.Int64Counter(topicEnqueueMetric, metric.WithUnit("{request}"),
		metric.WithDescription("Accepted requests and whether they reached the classification queue.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", topicEnqueueMetric, err)
	}
	if m.results, err = meter.Int64Counter(topicResultMetric, metric.WithUnit("{request}"),
		metric.WithDescription("How each queued request ended.")); err != nil {
		return nil, fmt.Errorf("create %s: %w", topicResultMetric, err)
	}
	if m.calls, err = meter.Float64Histogram(topicCallMetric, metric.WithUnit("s"),
		metric.WithDescription("Duration of each topic-guard call, by outcome."),
		metric.WithExplicitBucketBoundaries(.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10)); err != nil {
		return nil, fmt.Errorf("create %s: %w", topicCallMetric, err)
	}
	if m.callTexts, err = meter.Int64Histogram(topicCallTextsMetric, metric.WithUnit("{text}"),
		metric.WithDescription("Texts sent in each topic-guard call."),
		metric.WithExplicitBucketBoundaries(1, 2, 4, 8, 16, 32, 64, 128)); err != nil {
		return nil, fmt.Errorf("create %s: %w", topicCallTextsMetric, err)
	}
	if stats != nil {
		if err := registerStreamGauges(meter, stats); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func registerStreamGauges(meter metric.Meter, stats StreamStats) error {
	length, err := meter.Int64ObservableGauge(topicStreamLengthMetric, metric.WithUnit("{entry}"),
		metric.WithDescription("Entries waiting in the topic classification stream."))
	if err != nil {
		return fmt.Errorf("create %s: %w", topicStreamLengthMetric, err)
	}
	pending, err := meter.Int64ObservableGauge(topicStreamPendingMetric, metric.WithUnit("{entry}"),
		metric.WithDescription("Entries handed to a worker and not acknowledged yet."))
	if err != nil {
		return fmt.Errorf("create %s: %w", topicStreamPendingMetric, err)
	}
	_, err = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, streamStatsTimeout)
		defer cancel()
		l, p, err := stats(ctx)
		if err != nil {
			// A failed read skips this collection for the two gauges only;
			// returning it would fail the export of every other instrument.
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

func (m *TopicClassifierMetrics) Intake(outcome string) {
	if m == nil || !m.enabled {
		return
	}
	m.intake.Add(context.Background(), 1, m.attrs(outcome))
}

func (m *TopicClassifierMetrics) Enqueue(outcome string) {
	if m == nil || !m.enabled {
		return
	}
	m.enqueue.Add(context.Background(), 1, m.attrs(outcome))
}

func (m *TopicClassifierMetrics) Result(outcome string, n int) {
	if m == nil || !m.enabled || n <= 0 {
		return
	}
	m.results.Add(context.Background(), int64(n), m.attrs(outcome))
}

func (m *TopicClassifierMetrics) Call(outcome string, texts int, d time.Duration) {
	if m == nil || !m.enabled {
		return
	}
	attrs := m.attrs(outcome)
	m.calls.Record(context.Background(), d.Seconds(), attrs)
	m.callTexts.Record(context.Background(), int64(texts), attrs)
}

func (m *TopicClassifierMetrics) attrs(outcome string) metric.MeasurementOption {
	if opt, ok := m.outcomes[outcome]; ok {
		return opt
	}
	return metric.WithAttributes(outcomeKey.String(outcome))
}
