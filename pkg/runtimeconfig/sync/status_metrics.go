// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configsync

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	SnapshotLoadedMetric = "trustgate.configsync.snapshot.loaded"
	SnapshotSourceMetric = "trustgate.configsync.snapshot.source"
	SnapshotAgeMetric    = "trustgate.configsync.snapshot.age"
)

// RegisterSnapshotGauges exposes the snapshot state as observable gauges:
// loaded (0/1), source (1 for the current source, 0 for the other two, so a
// series per source always exists) and age in seconds (reported only while a
// snapshot is loaded).
//
// The meter must come from the installed global MeterProvider: an observable
// instrument created against the no-op provider never reports.
func RegisterSnapshotGauges(meter metric.Meter, status *SnapshotStatus) error {
	if _, err := meter.Int64ObservableGauge(
		SnapshotLoadedMetric,
		metric.WithDescription("1 when the pod has a config snapshot loaded, 0 when it has none"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if status.Info().State == SnapshotNone {
				o.Observe(0)
				return nil
			}
			o.Observe(1)
			return nil
		}),
	); err != nil {
		return fmt.Errorf("create snapshot loaded gauge: %w", err)
	}
	if _, err := meter.Int64ObservableGauge(
		SnapshotSourceMetric,
		metric.WithDescription("1 for the source of the served snapshot (none, lkg or live), 0 for the others; live means applied by a successful converge, not currently connected to the control plane"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			current := status.Info().State
			for _, state := range []SnapshotState{SnapshotNone, SnapshotLKG, SnapshotLive} {
				v := int64(0)
				if state == current {
					v = 1
				}
				o.Observe(v, metric.WithAttributes(attribute.String("source", string(state))))
			}
			return nil
		}),
	); err != nil {
		return fmt.Errorf("create snapshot source gauge: %w", err)
	}
	if _, err := meter.Float64ObservableGauge(
		SnapshotAgeMetric,
		metric.WithUnit("s"),
		metric.WithDescription("seconds since the served snapshot was applied by a converge, not since the last control-plane contact; absent while none is loaded"),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			if age, ok := status.Age(); ok {
				o.Observe(age.Seconds())
			}
			return nil
		}),
	); err != nil {
		return fmt.Errorf("create snapshot age gauge: %w", err)
	}
	return nil
}
