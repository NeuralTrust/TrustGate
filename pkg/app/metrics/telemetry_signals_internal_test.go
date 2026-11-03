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

package metrics

import (
	"context"
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func useManualMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })
	return reader
}

func collectByAttribute(t *testing.T, reader *sdkmetric.ManualReader, name, key string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					v, _ := dp.Attributes.Value(attribute.Key(key))
					out[v.AsString()] += dp.Value
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					v, _ := dp.Attributes.Value(attribute.Key(key))
					out[v.AsString()] = dp.Value
				}
			default:
				t.Fatalf("%s has unexpected data type %T", name, m.Data)
			}
		}
	}
	return out
}

func TestWorker_CountsDroppedEventsByReason(t *testing.T) {
	reader := useManualMeterProvider(t)
	w := NewWorker(internalTestLogger(), nil).(*worker)

	for i := 0; i < taskChanCapacity+1; i++ {
		w.enqueueTask(func() {}, "gw")
	}
	w.runTask(func() { panic("boom") })
	w.closed.Store(true)
	w.enqueueTask(func() {}, "gw")

	got := collectByAttribute(t, reader, droppedEventsMetric, "reason")
	assert.Equal(t, int64(1), got[dropReasonQueueFull])
	assert.Equal(t, int64(1), got[dropReasonPanic])
	assert.Equal(t, int64(1), got[dropReasonClosed])
}

func TestRegisterConfiguredExportersGauge_ReportsEveryClass(t *testing.T) {
	reader := useManualMeterProvider(t)

	RegisterConfiguredExportersGauge([]telemetrydomain.ExporterConfig{
		{Name: "metadata-otlp", Type: "otlp", Class: metricsschema.Metadata},
	}, internalTestLogger())

	got := collectByAttribute(t, reader, configuredExportersMetric, "data_class")
	assert.Equal(t, int64(1), got[string(metricsschema.Metadata)])
	raw, ok := got[string(metricsschema.Raw)]
	assert.True(t, ok, "a class with no exporter must be reported as 0, not omitted")
	assert.Zero(t, raw)
}
