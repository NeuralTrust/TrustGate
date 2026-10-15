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

package configsnapshot

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	// AdminSnapshotSourceMetric is 1 for the source of the snapshot the admin
	// serves and 0 for the others.
	AdminSnapshotSourceMetric = "trustgate.configsync.admin_snapshot_source"
	// AdminSnapshotAgeMetric is the age in seconds of the served snapshot.
	AdminSnapshotAgeMetric = "trustgate.configsync.admin_snapshot.age"
	// AdminLKGPersistMetric counts persist attempts by result.
	AdminLKGPersistMetric = "trustgate.configsync.admin_lkg.persist"
	// AdminLKGLoadMetric counts restored or rejected rows by result.
	AdminLKGLoadMetric = "trustgate.configsync.admin_lkg.load"
)

// RegisterAdminSnapshotGauges exposes where the admin's served snapshot came
// from and how old it is. The source series always exist, one per source, so an
// alert on source=persisted needs no absent() guard. The meter must come from
// the installed global MeterProvider.
func RegisterAdminSnapshotGauges(meter metric.Meter, d *Dispatcher) error {
	if _, err := meter.Int64ObservableGauge(
		AdminSnapshotSourceMetric,
		metric.WithDescription("1 for the source of the snapshot the admin serves (none, compiled or persisted), 0 for the others; persisted means restored after a restart with no compile succeeded since"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			current := d.Source()
			for _, s := range []SnapshotSource{SourceNone, SourceCompiled, SourcePersisted} {
				v := int64(0)
				if s == current {
					v = 1
				}
				o.Observe(v, metric.WithAttributes(attribute.String("source", s.String())))
			}
			return nil
		}),
	); err != nil {
		return fmt.Errorf("create admin snapshot source gauge: %w", err)
	}
	if _, err := meter.Float64ObservableGauge(
		AdminSnapshotAgeMetric,
		metric.WithUnit("s"),
		metric.WithDescription("seconds since the served snapshot was compiled; absent while the admin serves none"),
		metric.WithFloat64Callback(func(_ context.Context, o metric.Float64Observer) error {
			if age, ok := d.SnapshotAge(); ok {
				o.Observe(age.Seconds())
			}
			return nil
		}),
	); err != nil {
		return fmt.Errorf("create admin snapshot age gauge: %w", err)
	}
	return nil
}

func recordLKGPersist(ctx context.Context, result string) {
	addLKGCounter(ctx, AdminLKGPersistMetric, "snapshot persist attempts by result (ok, superseded, error)", result)
}

func recordLKGLoad(ctx context.Context, result string) {
	addLKGCounter(ctx, AdminLKGLoadMetric, "persisted snapshot rows seen at boot by result (ok, expired, key_mismatch, undecryptable, checksum_mismatch, error)", result)
}

// addLKGCounter resolves the instrument on each call: the SDK returns the same
// one for the same name, and both events are rare.
func addLKGCounter(ctx context.Context, name, description, result string) {
	counter, err := otel.Meter("trustgate/configsync").Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		slog.Warn("failed to create lkg counter", slog.String("metric", name), slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}
