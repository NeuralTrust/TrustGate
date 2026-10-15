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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// recordTenantCapsError counts a snapshot compiled without fresh tenant caps
// because they could not be read. The instrument is resolved on each call: the
// SDK returns the same one for the same name, and a compile is far too rare for
// the lookup to matter.
func recordTenantCapsError(ctx context.Context) {
	counter, err := otel.Meter(snapshotMeterName).Int64Counter(
		"trustgate.configsnapshot.tenant_caps.errors",
		metric.WithDescription("snapshots compiled without fresh tenant plan caps because reading them failed"),
	)
	if err != nil {
		slog.Warn("failed to create tenant caps error counter", slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1)
}
