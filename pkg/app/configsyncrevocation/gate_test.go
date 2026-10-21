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

package configsyncrevocation_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	appconfigsyncrevocation "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func revokedToken() domain.Identity {
	return domain.Identity{Scope: "gw-1", JTI: "jti-secret-value", IssuedAt: 100, Signed: true, InstanceScoped: true}
}

func snapshotRevoking(id domain.Identity) domain.Snapshot {
	return domain.NewSnapshot(domain.Revocations{JTIs: []domain.JTIRevocation{{Scope: id.Scope, JTI: id.JTI}}})
}

// useManualReader routes the global meter provider to a reader the test can
// collect from. Tests that call it must not run in parallel.
func useManualReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })
	return reader
}

func counterSum(t *testing.T, reader *sdkmetric.ManualReader, name string, attrs map[string]string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var total int64
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "%s is not an int64 sum", name)
		points:
			for _, dp := range sum.DataPoints {
				for key, want := range attrs {
					if got, ok := dp.Attributes.Value(attribute.Key(key)); !ok || got.AsString() != want {
						continue points
					}
				}
				total += dp.Value
			}
		}
	}
	return total
}

func TestGate_Modes(t *testing.T) {
	t.Parallel()
	valid := domain.Identity{Scope: "gw-1", JTI: "other", IssuedAt: 100, Signed: true, InstanceScoped: true}
	cases := []struct {
		mode        appconfigsyncrevocation.Mode
		id          domain.Identity
		wantAdmit   bool
		wantRevoked bool
	}{
		{appconfigsyncrevocation.ModeOff, revokedToken(), true, false},
		{appconfigsyncrevocation.ModeShadow, revokedToken(), true, false},
		{appconfigsyncrevocation.ModeEnforce, revokedToken(), false, true},
		{appconfigsyncrevocation.ModeEnforce, valid, true, false},
		{appconfigsyncrevocation.ModeEnforce, domain.Identity{}, true, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.mode)+"/"+tc.id.JTI, func(t *testing.T) {
			t.Parallel()
			gate := appconfigsyncrevocation.NewGate(tc.mode, discardLogger())
			gate.Replace(snapshotRevoking(revokedToken()))
			require.Equal(t, tc.wantAdmit, gate.Admit(context.Background(), tc.id))
			require.Equal(t, tc.wantRevoked, gate.Revoked(tc.id))
		})
	}
}

func TestGate_EmptyUntilReplaced(t *testing.T) {
	t.Parallel()
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeEnforce, discardLogger())
	require.True(t, gate.Admit(context.Background(), revokedToken()))
	gate.Replace(snapshotRevoking(revokedToken()))
	require.False(t, gate.Admit(context.Background(), revokedToken()))
	gate.Replace(domain.Snapshot{})
	require.True(t, gate.Admit(context.Background(), revokedToken()))
}

func TestGate_CountsPresentedTokensByModeAndReason(t *testing.T) {
	reader := useManualReader(t)
	shadow := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeShadow, discardLogger())
	shadow.Replace(domain.NewSnapshot(domain.Revocations{
		Marks: []domain.IssuedBeforeMark{{Scope: "gw-1", IssuedBefore: 1000}},
	}))
	require.True(t, shadow.Admit(context.Background(), revokedToken()))

	off := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeOff, discardLogger())
	off.Replace(snapshotRevoking(revokedToken()))
	require.True(t, off.Admit(context.Background(), revokedToken()))

	require.EqualValues(t, 1, counterSum(t, reader, appconfigsyncrevocation.PresentedMetric,
		map[string]string{"mode": "shadow", "reason": "issued_before"}))
	require.EqualValues(t, 1, counterSum(t, reader, appconfigsyncrevocation.PresentedMetric, nil))
}

func TestGate_NeverLogsTheRawJTI(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	gate := appconfigsyncrevocation.NewGate(appconfigsyncrevocation.ModeEnforce, slog.New(slog.NewTextHandler(&logs, nil)))
	gate.Replace(snapshotRevoking(revokedToken()))
	require.False(t, gate.Admit(context.Background(), revokedToken()))
	require.Contains(t, logs.String(), "revoked config-sync token presented")
	require.False(t, strings.Contains(logs.String(), revokedToken().JTI), "log line carries the raw jti: %s", logs.String())
}
