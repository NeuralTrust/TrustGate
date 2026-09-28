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
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

const (
	topicEventVerb = "topic_classification"

	attrTopicSchemaVersion = "trustgate.topic.schema_version"
	attrTopicTraceID       = "trustgate.topic.trace_id"
	attrTopicGatewayID     = "trustgate.topic.gateway_id"
	attrTopicTenantID      = "trustgate.topic.tenant_id"
	attrTopicRequestedOn   = "trustgate.topic.requested_on"
	attrTopicScores        = "trustgate.topic.scores"
	attrTopicMatched       = "trustgate.topic.matched"
	attrTopicMatchedCount  = "trustgate.topic.matched.count"
	attrTopicModelVersion  = "trustgate.topic.model_version"
	attrTopicCatalogHash   = "trustgate.topic.catalog_hash"
	attrTopicThreshold     = "trustgate.topic.threshold"
)

func topicEventName(schemaVersion int) string {
	if schemaVersion <= 0 {
		schemaVersion = metrics.SchemaVersion
	}
	return fmt.Sprintf("trustgate.%d.%s", schemaVersion, topicEventVerb)
}

// topicToRecord maps a topic classification to its own OTLP log record. Every
// attribute lives under trustgate.topic.*, and in particular the tenant is not
// sent as trustgate.tenant_id: the ClickHouse view that fills trustgate_events
// takes any record carrying that key, so reusing it would land each
// classification as one more request and double the request counts.
func topicToRecord(evt *events.TopicClassification) otellog.Record {
	var rec otellog.Record
	if evt == nil {
		return rec
	}
	rec.SetEventName(topicEventName(evt.SchemaVersion))
	if evt.OccurredOn > 0 {
		rec.SetTimestamp(time.UnixMilli(evt.OccurredOn))
	}
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(otellog.SeverityInfo)

	schemaVersion := evt.SchemaVersion
	if schemaVersion <= 0 {
		schemaVersion = metrics.SchemaVersion
	}
	attrs := []attribute.KeyValue{attribute.Int(attrTopicSchemaVersion, schemaVersion)}
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}
	appendStr(attrTopicTraceID, evt.TraceID)
	appendStr(attrTopicGatewayID, evt.GatewayID)
	appendStr(attrTopicTenantID, evt.TenantID)
	appendStr(attrTopicModelVersion, evt.ModelVersion)
	appendStr(attrTopicCatalogHash, evt.CatalogHash)
	if evt.RequestedOn > 0 {
		attrs = append(attrs, attribute.Int64(attrTopicRequestedOn, evt.RequestedOn))
	}
	scores, matched := evt.Scores, evt.Matched
	if scores == nil {
		scores = []events.TopicScore{}
	}
	if matched == nil {
		matched = []string{}
	}
	appendStr(attrTopicScores, jsonString(scores))
	appendStr(attrTopicMatched, jsonString(matched))
	attrs = append(attrs, attribute.Int(attrTopicMatchedCount, len(evt.Matched)))
	if evt.Threshold != nil {
		attrs = append(attrs, attribute.Float64(attrTopicThreshold, *evt.Threshold))
	}
	if evt.Retention != nil && evt.Retention.ExpiresAt > 0 {
		attrs = append(attrs, attribute.Int64(attrRetentionExpiresAt, evt.Retention.ExpiresAt))
		appendStr(attrRetentionPlan, evt.Retention.Plan)
	}
	rec.AddAttributes(attrs...)
	return rec
}
