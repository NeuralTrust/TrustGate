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

package configsyncrevocation

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	meterName = "trustgate/configsync"

	// PresentedMetric counts revoked config-sync tokens presented to the
	// control plane, by mode and by the rule that revoked them.
	PresentedMetric = "trustgate.configsync.revoked_token.presented"
	// RefreshMetric counts revocation reloads by result.
	RefreshMetric = "trustgate.configsync.revocation.refresh"
	// StreamsClosedMetric counts Sync streams closed because their token was revoked.
	StreamsClosedMetric = "trustgate.configsync.revocation.streams_closed"

	refreshOK    = "ok"
	refreshError = "error"
)

// The instruments are resolved on each call: the SDK returns the same one for
// the same name, and every caller is either rare (a revoked token, a closed
// stream) or periodic (a refresh), so the lookup never sits on the hot path.
func addCounter(ctx context.Context, name, description string, value int64, attrs ...attribute.KeyValue) {
	counter, err := otel.Meter(meterName).Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		slog.Warn("failed to create config-sync revocation counter",
			slog.String("metric", name), slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, value, metric.WithAttributes(attrs...))
}

func recordPresented(ctx context.Context, mode Mode, reason domain.Reason) {
	addCounter(ctx, PresentedMetric, "revoked config-sync tokens presented, by mode and revocation rule", 1,
		attribute.String("mode", string(mode)), attribute.String("reason", string(reason)))
}

func recordRefresh(ctx context.Context, result string) {
	addCounter(ctx, RefreshMetric, "config-sync revocation reloads, by result", 1,
		attribute.String("result", result))
}

func recordStreamsClosed(ctx context.Context, closed int) {
	addCounter(ctx, StreamsClosedMetric, "config-sync Sync streams closed because their token was revoked", int64(closed))
}
