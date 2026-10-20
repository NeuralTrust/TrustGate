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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	sessionRevocationsErrorMetric = "trustgate.configsnapshot.session_revocations.errors"
	sessionRevocationsFallback    = "fallback"
	sessionRevocationsFailClosed  = "fail_closed"
)

// recordSessionRevocationsError counts a session_revocations read that failed
// while compiling. fallback means the compile kept the last known listing;
// fail_closed means there was none, so the compile was refused. The instrument
// is resolved on each call: the SDK returns the same one for the same name, and
// a compile is far too rare for the lookup to matter.
func recordSessionRevocationsError(ctx context.Context, result string) {
	counter, err := otel.Meter(snapshotMeterName).Int64Counter(
		sessionRevocationsErrorMetric,
		metric.WithDescription("session revocation listings that failed during snapshot compile, by result (fallback reuses the last known set, fail_closed refuses the compile)"),
	)
	if err != nil {
		slog.Warn("failed to create session revocations error counter", slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}
