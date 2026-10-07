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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	snapshotMeterName  = "trustgate/configsnapshot"
	encodedBytesMetric = "trustgate.configsnapshot.encoded_bytes"
	scopesMetric       = "trustgate.configsnapshot.scopes"
	entitiesMetric     = "trustgate.configsnapshot.entities"
	flavourAttr        = "flavour"
	statAttr           = "stat"
	kindAttr           = "kind"
)

var (
	catalogBytesAttrs      = metric.WithAttributes(attribute.String(flavourAttr, "catalog"))
	globalBytesAttrs       = metric.WithAttributes(attribute.String(flavourAttr, "global"))
	scopedMaxBytesAttrs    = metric.WithAttributes(attribute.String(flavourAttr, "scoped"), attribute.String(statAttr, "max"))
	scopedTotalBytesAttrs  = metric.WithAttributes(attribute.String(flavourAttr, "scoped"), attribute.String(statAttr, "total"))
	authsAttrs             = metric.WithAttributes(attribute.String(kindAttr, "auths"))
	ownedAuthsAttrs        = metric.WithAttributes(attribute.String(kindAttr, "owned_auths"))
	personalConsumersAttrs = metric.WithAttributes(attribute.String(kindAttr, "personal_consumers"))
	personalLinksAttrs     = metric.WithAttributes(attribute.String(kindAttr, "personal_links"))
)

type snapshotEntities struct {
	auths             int64
	ownedAuths        int64
	personalConsumers int64
	personalLinks     int64
}

func (n *snapshotEntities) add(snapshot *readmodel.Snapshot) {
	data := snapshot.Data()
	n.auths += int64(len(data.Auths))
	for i := range data.Auths {
		if data.Auths[i].IsOwned() {
			n.ownedAuths++
		}
	}
	for i := range data.Consumers {
		if data.Consumers[i].IsPersonal() {
			n.personalConsumers++
			n.personalLinks += int64(len(data.Consumers[i].AuthLinks))
		}
	}
}

type scopeSizes struct {
	count        int
	largest      string
	largestBytes int
	totalBytes   int
}

func (s *scopeSizes) add(scope string, size int) {
	s.count++
	s.totalBytes += size
	if s.count == 1 || size > s.largestBytes || (size == s.largestBytes && scope < s.largest) {
		s.largest, s.largestBytes = scope, size
	}
}

func recordSnapshotPublish(ctx context.Context, logger *slog.Logger, compiled compiledSnapshot) {
	meter := otel.Meter(snapshotMeterName)
	if gauge, ok := snapshotGauge(meter, logger, encodedBytesMetric, "By", "encoded size of the last published config snapshot: catalog, global, and the largest (stat=max) and summed (stat=total) scoped snapshots"); ok {
		recordEncodedBytes(ctx, gauge, compiled)
	}
	if compiled.scoped != nil {
		if gauge, ok := snapshotGauge(meter, logger, scopesMetric, "{scope}", "scoped snapshots in the last published config snapshot"); ok {
			gauge.Record(ctx, int64(compiled.scopes.count))
		}
	}
	if gauge, ok := snapshotGauge(meter, logger, entitiesMetric, "{entity}", "entities in the last published config snapshot, per kind, every gateway counted once"); ok {
		recordEntityCounts(ctx, gauge, compiled.entities)
	}
}

func snapshotGauge(meter metric.Meter, logger *slog.Logger, name, unit, description string) (metric.Int64Gauge, bool) {
	gauge, err := meter.Int64Gauge(name, metric.WithUnit(unit), metric.WithDescription(description))
	if err != nil {
		logger.Warn("failed to create config snapshot gauge",
			slog.String("component", component), slog.String("instrument", name), slog.String("error", err.Error()))
		return nil, false
	}
	return gauge, true
}

func recordEncodedBytes(ctx context.Context, gauge metric.Int64Gauge, compiled compiledSnapshot) {
	gauge.Record(ctx, int64(len(compiled.raw)), globalBytesAttrs)
	if compiled.scoped == nil {
		return
	}
	gauge.Record(ctx, int64(compiled.catalogBytes), catalogBytesAttrs)
	gauge.Record(ctx, int64(compiled.scopes.largestBytes), scopedMaxBytesAttrs)
	gauge.Record(ctx, int64(compiled.scopes.totalBytes), scopedTotalBytesAttrs)
}

func recordEntityCounts(ctx context.Context, gauge metric.Int64Gauge, n snapshotEntities) {
	gauge.Record(ctx, n.auths, authsAttrs)
	gauge.Record(ctx, n.ownedAuths, ownedAuthsAttrs)
	gauge.Record(ctx, n.personalConsumers, personalConsumersAttrs)
	gauge.Record(ctx, n.personalLinks, personalLinksAttrs)
}
