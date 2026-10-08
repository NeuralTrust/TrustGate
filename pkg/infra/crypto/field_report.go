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

package crypto

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ReportUnreadableField logs at error, and counts, a stored value of table
// that could not be decrypted and is returned empty. It records the row id,
// the field path and the key id the value names, never the value.
func ReportUnreadableField(ctx context.Context, table, rowID, field, stored string, err error) {
	slog.ErrorContext(ctx, "stored credential cannot be decrypted; returning it empty",
		slog.String("component", "stored_secrets"),
		slog.String("table", table),
		slog.String("row_id", rowID),
		slog.String("field", field),
		slog.String("key_id", SealedKeyID(stored)),
		slog.String("error", err.Error()))
	counter, cerr := otel.Meter("trustgate/stored_secrets").Int64Counter(
		"trustgate.stored_secrets.unreadable_fields",
		metric.WithDescription("stored credentials returned empty because they could not be decrypted"),
	)
	if cerr != nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("table", table)))
}
