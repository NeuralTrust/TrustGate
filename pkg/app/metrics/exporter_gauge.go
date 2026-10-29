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
	"log/slog"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const configuredExportersMetric = "agentgateway.telemetry.exporters.configured"

// RegisterConfiguredExportersGauge reports the default exporters per data
// class, so a gateway exporting nothing for a class shows up as a 0 rather
// than as an absence of data.
func RegisterConfiguredExportersGauge(defaults []telemetrydomain.ExporterConfig, logger *slog.Logger) {
	counts := map[metricsschema.DataClass]int64{metricsschema.Metadata: 0, metricsschema.Raw: 0}
	for _, cfg := range defaults {
		counts[cfg.Class]++
	}
	_, err := otel.Meter("trustgate/metrics").Int64ObservableGauge(
		configuredExportersMetric,
		metric.WithDescription("default telemetry exporters configured, by data class"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for class, n := range counts {
				o.Observe(n, metric.WithAttributes(attribute.String("data_class", string(class))))
			}
			return nil
		}),
	)
	if err != nil {
		logger.Warn("failed to create configured-exporters gauge",
			slog.String("component", "metrics"), slog.String("error", err.Error()))
	}
}
