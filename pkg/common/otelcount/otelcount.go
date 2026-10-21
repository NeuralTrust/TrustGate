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


// Package otelcount adds to OpenTelemetry counters resolved by name.
package otelcount

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Add adds value to the int64 counter name on the meter meterName. The counter
// is resolved on each call: the SDK returns the same instrument for the same
// name, which suits callers on rare or periodic paths. If the counter cannot
// be created the value is dropped and a warning logged, so a metric never
// fails its caller.
func Add(ctx context.Context, meterName, name, description string, value int64, attrs ...attribute.KeyValue) {
	counter, err := otel.Meter(meterName).Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		slog.Warn("failed to create counter",
			slog.String("meter", meterName), slog.String("metric", name), slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, value, metric.WithAttributes(attrs...))
}
