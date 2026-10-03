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

package otlp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func labelsEvent() *events.TrafficLabels {
	return &events.TrafficLabels{
		SchemaVersion: events.SchemaVersion,
		TraceID:       "trace-123",
		GatewayID:     "gw-1",
		ConsumerID:    "consumer-1",
		TenantID:      "tenant-1",
		OccurredOn:    time.Date(2026, 9, 28, 10, 0, 5, 0, time.UTC).UnixMilli(),
		RequestedOn:   time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC).UnixMilli(),
		Retention:     &events.Retention{Plan: "enterprise", ExpiresAt: 1_900_000_000_000},
		Matched:       []events.LabelRef{{ID: "l-1", Name: "Billing"}},
		Evaluated:     []events.LabelRef{{ID: "l-1", Name: "Billing"}, {ID: "l-2", Name: "Legal"}},
		RegistryID:    "reg-1",
		Model:         "gpt-4o-mini",
		CatalogHash:   "abc",
		InputTokens:   120,
		OutputTokens:  9,
		LatencyMs:     340,
	}
}

func newMemExporter(t *testing.T) (*Exporter, *memExporter) {
	t.Helper()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)
	t.Cleanup(exp.Close)
	return exp, mem
}

func TestExporter_PublishTrafficLabelsEmitsItsOwnRecord(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)

	require.NoError(t, exp.PublishTrafficLabels(context.Background(), labelsEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, fmt.Sprintf("trustgate.%d.traffic_labels", events.SchemaVersion), rec.EventName())
	assert.NotEqual(t, eventName(events.SchemaVersion, metrics.Metadata), rec.EventName())
	assert.Equal(t, time.Date(2026, 9, 28, 10, 0, 5, 0, time.UTC), rec.Timestamp().UTC())

	str := func(key string) string {
		v, ok := recordAttr(rec, key)
		require.True(t, ok, "missing %s", key)
		return v.AsString()
	}
	num := func(key string) int64 {
		v, ok := recordAttr(rec, key)
		require.True(t, ok, "missing %s", key)
		return v.AsInt64()
	}
	assert.Equal(t, "trace-123", str(attrLabelTraceID))
	assert.Equal(t, "gw-1", str(attrLabelGatewayID))
	assert.Equal(t, "consumer-1", str(attrLabelConsumerID))
	assert.Equal(t, "tenant-1", str(attrLabelTenantID))
	assert.Equal(t, "reg-1", str(attrLabelRegistryID))
	assert.Equal(t, "gpt-4o-mini", str(attrLabelModel))
	assert.Equal(t, "abc", str(attrLabelCatalogHash))
	assert.JSONEq(t, `[{"id":"l-1","name":"Billing"}]`, str(attrLabelMatched))
	assert.JSONEq(t, `[{"id":"l-1","name":"Billing"},{"id":"l-2","name":"Legal"}]`, str(attrLabelEvaluated))
	assert.Equal(t, "enterprise", str(attrRetentionPlan))
	assert.Equal(t, int64(events.SchemaVersion), num(attrLabelSchemaVersion))
	assert.Equal(t, int64(1), num(attrLabelMatchedCount))
	assert.Equal(t, int64(120), num(attrLabelInputTokens))
	assert.Equal(t, int64(9), num(attrLabelOutputTokens))
	assert.Equal(t, int64(340), num(attrLabelLatencyMs))
	assert.Equal(t, time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC).UnixMilli(), num(attrLabelRequestedOn))
}

func TestExporter_PublishTrafficLabelsStaysOutOfTheRequestNamespace(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)

	require.NoError(t, exp.PublishTrafficLabels(context.Background(), labelsEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	_, hasTenant := recordAttr(records[0], attrTenantID)
	assert.False(t, hasTenant, "a label record must never carry %s", attrTenantID)

	allowed := map[string]bool{attrRetentionExpiresAt: true, attrRetentionPlan: true}
	records[0].WalkAttributes(func(kv attribute.KeyValue) bool {
		key := string(kv.Key)
		assert.True(t, strings.HasPrefix(key, "trustgate.label.") || allowed[key], "unexpected attribute %s", key)
		return true
	})
}

func TestExporter_PublishTrafficLabelsWithoutMatches(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	evt := labelsEvent()
	evt.Matched = nil
	evt.InputTokens, evt.OutputTokens, evt.LatencyMs = 0, 0, 0
	evt.Retention = nil

	require.NoError(t, exp.PublishTrafficLabels(context.Background(), evt))

	rec := mem.all()[0]
	matched, _ := recordAttr(rec, attrLabelMatched)
	assert.Equal(t, "[]", matched.AsString(), "no match is an empty list, not null")
	count, _ := recordAttr(rec, attrLabelMatchedCount)
	assert.Equal(t, int64(0), count.AsInt64())
	tokens, ok := recordAttr(rec, attrLabelInputTokens)
	require.True(t, ok, "unknown usage is reported as 0")
	assert.Equal(t, int64(0), tokens.AsInt64())
	_, hasRetention := recordAttr(rec, attrRetentionExpiresAt)
	assert.False(t, hasRetention)
}

func TestExporter_PublishTrafficLabelsSkipsRawExporters(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	exp.SetDataClass(metrics.Raw)

	require.NoError(t, exp.PublishTrafficLabels(context.Background(), labelsEvent()))
	assert.Empty(t, mem.all())
}

func TestExporter_PublishTrafficLabelsNilAndClosed(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	require.NoError(t, exp.PublishTrafficLabels(context.Background(), nil))
	assert.Empty(t, mem.all())

	exp.Close()
	require.ErrorIs(t, exp.PublishTrafficLabels(context.Background(), labelsEvent()), errExporterClosed)
}
