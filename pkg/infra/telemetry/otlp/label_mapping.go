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
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

const (
	labelsEventVerb = "traffic_labels"

	// Kept out of trustgate.tenant_id: the trustgate_events view would count the record as a request.
	attrLabelSchemaVersion = "trustgate.label.schema_version"
	attrLabelTraceID       = "trustgate.label.trace_id"
	attrLabelGatewayID     = "trustgate.label.gateway_id"
	attrLabelConsumerID    = "trustgate.label.consumer_id"
	attrLabelTenantID      = "trustgate.label.tenant_id"
	attrLabelRequestedOn   = "trustgate.label.requested_on"
	attrLabelResults       = "trustgate.label.results"
	attrLabelResultsCount  = "trustgate.label.results.count"
	attrLabelRegistryID    = "trustgate.label.registry_id"
	attrLabelModel         = "trustgate.label.model"
	attrLabelCatalogHash   = "trustgate.label.catalog_hash"
	attrLabelInputTokens   = "trustgate.label.usage.input_tokens"
	attrLabelOutputTokens  = "trustgate.label.usage.output_tokens"
	attrLabelLatencyMs     = "trustgate.label.latency_ms"
)

// labelsEventName follows the naming of the request events; the payload's own
// version travels in trustgate.label.schema_version.
func labelsEventName() string {
	return fmt.Sprintf("trustgate.%d.%s", events.SchemaVersion, labelsEventVerb)
}

func labelsToRecord(evt *events.TrafficLabels) otellog.Record {
	var rec otellog.Record
	if evt == nil {
		return rec
	}
	rec.SetEventName(labelsEventName())
	if evt.OccurredOn > 0 {
		rec.SetTimestamp(time.UnixMilli(evt.OccurredOn))
	}
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(otellog.SeverityInfo)

	schemaVersion := evt.SchemaVersion
	if schemaVersion <= 0 {
		schemaVersion = events.TrafficLabelsSchemaVersion
	}
	attrs := []attribute.KeyValue{attribute.Int(attrLabelSchemaVersion, schemaVersion)}
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}
	appendStr(attrLabelTraceID, evt.TraceID)
	appendStr(attrLabelGatewayID, evt.GatewayID)
	appendStr(attrLabelConsumerID, evt.ConsumerID)
	appendStr(attrLabelTenantID, evt.TenantID)
	appendStr(attrLabelRegistryID, evt.RegistryID)
	appendStr(attrLabelModel, evt.Model)
	appendStr(attrLabelCatalogHash, evt.CatalogHash)
	if evt.RequestedOn > 0 {
		attrs = append(attrs, attribute.Int64(attrLabelRequestedOn, evt.RequestedOn))
	}
	attrs = append(attrs,
		attribute.String(attrLabelResults, jsonString(nonNilResults(evt.Results))),
		attribute.Int(attrLabelResultsCount, len(evt.Results)),
		attribute.Int(attrLabelInputTokens, max(evt.InputTokens, 0)),
		attribute.Int(attrLabelOutputTokens, max(evt.OutputTokens, 0)),
		attribute.Int64(attrLabelLatencyMs, max(evt.LatencyMs, 0)),
	)
	if evt.Retention != nil && evt.Retention.ExpiresAt > 0 {
		attrs = append(attrs, attribute.Int64(attrRetentionExpiresAt, evt.Retention.ExpiresAt))
		appendStr(attrRetentionPlan, evt.Retention.Plan)
	}
	rec.AddAttributes(attrs...)
	return rec
}

func nonNilResults(results []events.LabelResult) []events.LabelResult {
	if results == nil {
		return []events.LabelResult{}
	}
	return results
}
