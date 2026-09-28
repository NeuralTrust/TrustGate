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

func topicEvent() *events.TopicClassification {
	threshold := 0.6
	return &events.TopicClassification{
		SchemaVersion: events.SchemaVersion,
		TraceID:       "trace-123",
		GatewayID:     "gw-1",
		TenantID:      "tenant-1",
		OccurredOn:    time.Date(2026, 9, 28, 10, 0, 5, 0, time.UTC).UnixMilli(),
		RequestedOn:   time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC).UnixMilli(),
		Retention:     &events.Retention{Plan: "enterprise", ExpiresAt: 1_900_000_000_000},
		Scores: []events.TopicScore{
			{Topic: "billing", Probability: 0.92, Matched: true},
			{Topic: "legal", Probability: 0.1},
		},
		Matched:      []string{"billing"},
		ModelVersion: "topic-guard@r7+cal3",
		CatalogHash:  "abc",
		Threshold:    &threshold,
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

func TestExporter_PublishTopicEmitsItsOwnRecord(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)

	require.NoError(t, exp.PublishTopic(context.Background(), topicEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, fmt.Sprintf("trustgate.%d.topic_classification", events.SchemaVersion), rec.EventName())
	assert.NotEqual(t, eventName(events.SchemaVersion, metrics.Metadata), rec.EventName())
	assert.Equal(t, time.Date(2026, 9, 28, 10, 0, 5, 0, time.UTC), rec.Timestamp().UTC())

	str := func(key string) string {
		v, ok := recordAttr(rec, key)
		require.True(t, ok, "missing %s", key)
		return v.AsString()
	}
	assert.Equal(t, "trace-123", str(attrTopicTraceID))
	assert.Equal(t, "gw-1", str(attrTopicGatewayID))
	assert.Equal(t, "tenant-1", str(attrTopicTenantID))
	assert.Equal(t, "topic-guard@r7+cal3", str(attrTopicModelVersion))
	assert.Equal(t, `["billing"]`, str(attrTopicMatched))
	assert.JSONEq(t, `[{"topic":"billing","probability":0.92,"matched":true},{"topic":"legal","probability":0.1,"matched":false}]`, str(attrTopicScores))
	assert.Equal(t, "enterprise", str(attrRetentionPlan))

	_, hasWindows := recordAttr(rec, "trustgate.topic.windows")
	assert.False(t, hasWindows, "the window count follows the prompt length, so it is not emitted")
	threshold, _ := recordAttr(rec, attrTopicThreshold)
	assert.InDelta(t, 0.6, threshold.AsFloat64(), 1e-9)
	requested, _ := recordAttr(rec, attrTopicRequestedOn)
	assert.Equal(t, time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC).UnixMilli(), requested.AsInt64())
}

// The ClickHouse view behind trustgate_events keys on trustgate.tenant_id; a
// topic record carrying it would be counted as a request.
func TestExporter_PublishTopicStaysOutOfTheRequestNamespace(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)

	require.NoError(t, exp.PublishTopic(context.Background(), topicEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	_, hasTenant := recordAttr(records[0], attrTenantID)
	assert.False(t, hasTenant, "a topic record must never carry %s", attrTenantID)

	allowed := map[string]bool{attrRetentionExpiresAt: true, attrRetentionPlan: true}
	records[0].WalkAttributes(func(kv attribute.KeyValue) bool {
		key := string(kv.Key)
		assert.True(t, strings.HasPrefix(key, "trustgate.topic.") || allowed[key], "unexpected attribute %s", key)
		return true
	})
}

func TestExporter_PublishTopicWithoutMatches(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	evt := topicEvent()
	evt.Matched = nil
	evt.Threshold = nil
	evt.Retention = nil

	require.NoError(t, exp.PublishTopic(context.Background(), evt))

	rec := mem.all()[0]
	matched, _ := recordAttr(rec, attrTopicMatched)
	assert.Equal(t, "[]", matched.AsString(), "no match is an empty list, not null")
	_, hasThreshold := recordAttr(rec, attrTopicThreshold)
	assert.False(t, hasThreshold)
	_, hasRetention := recordAttr(rec, attrRetentionExpiresAt)
	assert.False(t, hasRetention)
}

func TestExporter_PublishTopicSkipsRawExporters(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	exp.SetDataClass(metrics.Raw)

	require.NoError(t, exp.PublishTopic(context.Background(), topicEvent()))
	assert.Empty(t, mem.all())
}

func TestExporter_PublishTopicNilAndClosed(t *testing.T) {
	t.Parallel()
	exp, mem := newMemExporter(t)
	require.NoError(t, exp.PublishTopic(context.Background(), nil))
	assert.Empty(t, mem.all())

	exp.Close()
	require.ErrorIs(t, exp.PublishTopic(context.Background(), topicEvent()), errExporterClosed)
}
