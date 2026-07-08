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

package telemetry

import (
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
)

// LogPublish emits a debug line each time an exporter hands an event off to its
// sink. It logs only non-sensitive identifiers so it stays safe for every data
// class; request/response bodies are never logged.
func LogPublish(logger *slog.Logger, exporter string, class metrics.DataClass, evt *events.Event) {
	if logger == nil || evt == nil {
		return
	}
	logger.Debug("event published to exporter",
		slog.String("exporter", exporter),
		slog.String("class", string(class)),
		slog.Int("schema_version", evt.SchemaVersion),
		slog.String("trace_id", evt.TraceID),
		slog.String("gateway_id", evt.GatewayID),
		slog.String("tenant_id", evt.TenantID),
	)
}
