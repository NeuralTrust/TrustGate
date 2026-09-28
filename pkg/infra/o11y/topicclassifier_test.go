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
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]metricdata.Metrics{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func sumByOutcome(t *testing.T, m metricdata.Metrics) map[string]int64 {
	t.Helper()
	sum, ok := m.Data.(metricdata.Sum[int64])
	require.True(t, ok, "%s is not an int64 sum", m.Name)
	out := map[string]int64{}
	for _, dp := range sum.DataPoints {
		outcome, _ := dp.Attributes.Value(attribute.Key("outcome"))
		assert.Equal(t, 1, dp.Attributes.Len(), "outcome must be the only label")
		out[outcome.AsString()] = dp.Value
	}
	return out
}

func TestTopicClassifierMetrics_RecordsBoundedOutcomes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	m, err := newTopicClassifierMetrics(provider.Meter(instrumentationScope), nil)
	require.NoError(t, err)

	m.Intake(topicclassifier.OutcomeAccepted)
	m.Intake(topicclassifier.OutcomeAccepted)
	m.Intake(topicclassifier.OutcomeBufferFull)
	m.Enqueue(topicclassifier.OutcomeQueued)
	m.Result(topicclassifier.OutcomeClassified, 3)
	m.Result(topicclassifier.OutcomeCacheHit, 0)
	m.Call(topicclassifier.OutcomeOK, 4, 80*time.Millisecond)

	got := collect(t, reader)
	assert.Equal(t, map[string]int64{"accepted": 2, "buffer_full": 1}, sumByOutcome(t, got[topicIntakeMetric]))
	assert.Equal(t, map[string]int64{"queued": 1}, sumByOutcome(t, got[topicEnqueueMetric]))
	assert.Equal(t, map[string]int64{"classified": 3}, sumByOutcome(t, got[topicResultMetric]), "zero counts are not recorded")

	calls, ok := got[topicCallMetric].Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.Len(t, calls.DataPoints, 1)
	assert.Equal(t, uint64(1), calls.DataPoints[0].Count)
	assert.InDelta(t, 0.08, calls.DataPoints[0].Sum, 1e-9)
}

func TestTopicClassifierMetrics_StreamGauges(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	fail := false
	stats := func(context.Context) (int64, int64, error) {
		if fail {
			return 0, 0, errors.New("redis down")
		}
		return 42, 7, nil
	}
	_, err := newTopicClassifierMetrics(provider.Meter(instrumentationScope), stats)
	require.NoError(t, err)

	got := collect(t, reader)
	length, ok := got[topicStreamLengthMetric].Data.(metricdata.Gauge[int64])
	require.True(t, ok)
	assert.Equal(t, int64(42), length.DataPoints[0].Value)
	pending, ok := got[topicStreamPendingMetric].Data.(metricdata.Gauge[int64])
	require.True(t, ok)
	assert.Equal(t, int64(7), pending.DataPoints[0].Value)

	fail = true
	got = collect(t, reader)
	_, present := got[topicStreamLengthMetric]
	assert.False(t, present, "a failed read skips the gauge instead of failing the collection")
}

func TestTopicClassifierMetrics_DisabledIsInert(t *testing.T) {
	m, err := NewTopicClassifierMetrics(&config.Config{}, nil, nil)
	require.NoError(t, err)
	m.Intake(topicclassifier.OutcomeAccepted)
	m.Enqueue(topicclassifier.OutcomeQueued)
	m.Result(topicclassifier.OutcomeClassified, 1)
	m.Call(topicclassifier.OutcomeOK, 1, time.Millisecond)

	var nilMetrics *TopicClassifierMetrics
	nilMetrics.Intake(topicclassifier.OutcomeAccepted)
}
