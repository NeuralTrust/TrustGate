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

package telemetry_test

import (
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storedTelemetry() *telemetrydomain.Telemetry {
	return &telemetrydomain.Telemetry{
		Exporters: []telemetrydomain.ExporterConfig{
			{Name: "otlp", Settings: map[string]any{
				"endpoint": "https://collector.example.com",
				"headers":  map[string]any{"Authorization": "Bearer secret-token"},
			}},
			{Name: "audit", Type: "postgres", Settings: map[string]any{
				"dsn":   "postgres://user:pa55@db.example.com/metrics",
				"table": "sensible_events",
			}},
			{Name: "custom", Settings: map[string]any{"host": "kafka", "headers": "kept"}},
		},
	}
}

func TestWithoutCredentials_DropsHeadersAndDSN(t *testing.T) {
	t.Parallel()
	stored := storedTelemetry()

	got := stored.WithoutCredentials()

	require.Len(t, got.Exporters, 3)
	assert.Equal(t, map[string]any{"endpoint": "https://collector.example.com"}, got.Exporters[0].Settings)
	assert.Equal(t, map[string]any{"table": "sensible_events"}, got.Exporters[1].Settings)
	assert.Equal(t, map[string]any{"host": "kafka", "headers": "kept"}, got.Exporters[2].Settings)
}

func TestWithoutCredentials_LeavesInputUntouched(t *testing.T) {
	t.Parallel()
	stored := storedTelemetry()

	_ = stored.WithoutCredentials()

	assert.Equal(t, storedTelemetry(), stored)
}

func TestWithoutCredentials_MatchesKeysCaseInsensitively(t *testing.T) {
	t.Parallel()
	stored := &telemetrydomain.Telemetry{Exporters: []telemetrydomain.ExporterConfig{
		{Name: "otlp", Settings: map[string]any{"Headers": map[string]any{"X-Key": "v"}}},
		{Name: "postgres", Settings: map[string]any{"DSN": "postgres://u:p@h/db"}},
	}}

	got := stored.WithoutCredentials()

	assert.Empty(t, got.Exporters[0].Settings)
	assert.Empty(t, got.Exporters[1].Settings)
}

func TestWithoutCredentials_Nil(t *testing.T) {
	t.Parallel()
	var tel *telemetrydomain.Telemetry
	assert.Nil(t, tel.WithoutCredentials())
}

func TestKeepOmittedCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		incoming []telemetrydomain.ExporterConfig
		want     []map[string]any
		wantErr  string
	}{
		{
			name: "read-modify-write keeps stored headers and dsn",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{"endpoint": "https://collector.example.com"}},
				{Name: "audit", Type: "postgres", Settings: map[string]any{"table": "sensible_events"}},
			},
			want: []map[string]any{
				{"endpoint": "https://collector.example.com", "headers": map[string]any{"Authorization": "Bearer secret-token"}},
				{"dsn": "postgres://user:pa55@db.example.com/metrics", "table": "sensible_events"},
			},
		},
		{
			name: "sent values replace stored ones",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{
					"endpoint": "https://collector.example.com",
					"headers":  map[string]any{"Authorization": "Bearer new"},
				}},
				{Name: "audit", Type: "postgres", Settings: map[string]any{"dsn": ""}},
			},
			want: []map[string]any{
				{"endpoint": "https://collector.example.com", "headers": map[string]any{"Authorization": "Bearer new"}},
				{"dsn": ""},
			},
		},
		{
			name: "explicit null clears",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{"endpoint": "https://collector.example.com", "headers": nil}},
			},
			want: []map[string]any{{"endpoint": "https://collector.example.com"}},
		},
		{
			name: "changed endpoint without headers is rejected",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{"endpoint": "https://attacker.example.com"}},
			},
			wantErr: "settings.endpoint",
		},
		{
			name: "changed tls without headers is rejected",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{
					"endpoint": "https://collector.example.com",
					"tls":      map[string]any{"skip_verify": true},
				}},
			},
			wantErr: "settings.tls",
		},
		{
			name: "changed endpoint with new headers is accepted",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "otlp", Settings: map[string]any{
					"endpoint": "https://other.example.com",
					"headers":  map[string]any{},
				}},
			},
			want: []map[string]any{{"endpoint": "https://other.example.com", "headers": map[string]any{}}},
		},
		{
			name: "type change carries nothing over",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "audit", Type: "otlp", Settings: map[string]any{"endpoint": "https://other.example.com"}},
			},
			want: []map[string]any{{"endpoint": "https://other.example.com"}},
		},
		{
			name: "new exporter carries nothing over",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "pg2", Type: "postgres", Settings: nil},
			},
			want: []map[string]any{nil},
		},
		{
			name: "nil settings get the stored dsn",
			incoming: []telemetrydomain.ExporterConfig{
				{Name: "audit", Type: "postgres"},
			},
			want: []map[string]any{{"dsn": "postgres://user:pa55@db.example.com/metrics"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			incoming := &telemetrydomain.Telemetry{Exporters: tt.incoming}

			err := telemetrydomain.KeepOmittedCredentials(incoming, storedTelemetry())

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			got := make([]map[string]any, len(incoming.Exporters))
			for i, e := range incoming.Exporters {
				got[i] = e.Settings
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeepOmittedCredentials_NilInputs(t *testing.T) {
	t.Parallel()
	require.NoError(t, telemetrydomain.KeepOmittedCredentials(nil, storedTelemetry()))

	incoming := &telemetrydomain.Telemetry{Exporters: []telemetrydomain.ExporterConfig{{Name: "otlp"}}}
	require.NoError(t, telemetrydomain.KeepOmittedCredentials(incoming, nil))
	assert.Nil(t, incoming.Exporters[0].Settings)
}
