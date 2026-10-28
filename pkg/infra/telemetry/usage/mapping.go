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

package usage

import (
	"strconv"
	"time"

	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

// EventName is the OTLP event name of every usage record.
const EventName = "usage.1.record"

const (
	attrSchemaVersion            = "usage.schema_version"
	attrEventID                  = "usage.event_id"
	attrProduct                  = "usage.product"
	attrTenantID                 = "usage.tenant_id"
	attrOccurredOn               = "usage.occurred_on"
	attrTraceID                  = "usage.trace_id"
	attrGatewayID                = "usage.gateway_id"
	attrConsumerID               = "usage.consumer_id"
	attrRequests                 = "usage.requests"
	attrSmartRoutingExecutions   = "usage.smart_routing_executions"
	attrTopicClassificationChars = "usage.topic_classification_chars"

	occurredOnLayout = "2006-01-02T15:04:05.000Z07:00"
)

func toLogRecord(r usagedomain.Record, observed time.Time) otellog.Record {
	var rec otellog.Record
	rec.SetEventName(EventName)
	rec.SetTimestamp(r.OccurredOn)
	rec.SetObservedTimestamp(observed)
	rec.SetSeverity(otellog.SeverityInfo)

	attrs := []attribute.KeyValue{
		attribute.String(attrSchemaVersion, strconv.Itoa(usagedomain.SchemaVersion)),
		attribute.String(attrEventID, r.EventID),
		attribute.String(attrProduct, usagedomain.Product),
		attribute.String(attrTenantID, r.TenantID),
		attribute.String(attrOccurredOn, r.OccurredOn.UTC().Format(occurredOnLayout)),
		attribute.String(attrTraceID, r.TraceID),
	}
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}
	appendUnit := func(key string, value int64) {
		if value > 0 {
			attrs = append(attrs, attribute.Int64(key, value))
		}
	}
	appendStr(attrGatewayID, r.GatewayID)
	appendStr(attrConsumerID, r.ConsumerID)
	appendUnit(attrRequests, r.Requests)
	appendUnit(attrSmartRoutingExecutions, r.SmartRoutingExecutions)
	appendUnit(attrTopicClassificationChars, r.TopicClassificationChars)
	rec.AddAttributes(attrs...)
	return rec
}
