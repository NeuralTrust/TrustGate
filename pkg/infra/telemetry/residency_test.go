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
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/postgres"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRawResidency(t *testing.T) {
	rawOTLP := telemetrydomain.ExporterConfig{
		Name:  "raw-otlp",
		Type:  otlp.ExporterName,
		Class: metricsschema.Raw,
	}
	rawPostgres := telemetrydomain.ExporterConfig{
		Name:  "sensible-pg",
		Type:  postgres.ExporterName,
		Class: metricsschema.Raw,
	}
	metadataOTLP := telemetrydomain.ExporterConfig{
		Name:  "metadata-otlp",
		Type:  otlp.ExporterName,
		Class: metricsschema.Metadata,
	}
	rawOTLPByName := telemetrydomain.ExporterConfig{
		Name:  otlp.ExporterName,
		Class: metricsschema.Raw,
	}

	tests := []struct {
		name        string
		configs     []telemetrydomain.ExporterConfig
		hybrid      bool
		allowRemote bool
		wantErr     bool
	}{
		{
			name:    "hybrid rejects raw over otlp",
			configs: []telemetrydomain.ExporterConfig{metadataOTLP, rawOTLP},
			hybrid:  true,
			wantErr: true,
		},
		{
			name:    "hybrid rejects raw over otlp declared by name",
			configs: []telemetrydomain.ExporterConfig{rawOTLPByName},
			hybrid:  true,
			wantErr: true,
		},
		{
			name:        "explicit override keeps raw over otlp",
			configs:     []telemetrydomain.ExporterConfig{rawOTLP},
			hybrid:      true,
			allowRemote: true,
		},
		{
			name:    "hybrid default keeps raw in postgres",
			configs: []telemetrydomain.ExporterConfig{metadataOTLP, rawPostgres},
			hybrid:  true,
		},
		{
			name:    "hybrid still ships metadata over otlp",
			configs: []telemetrydomain.ExporterConfig{metadataOTLP},
			hybrid:  true,
		},
		{
			name:    "hosted deployment keeps raw over otlp",
			configs: []telemetrydomain.ExporterConfig{rawOTLP},
			hybrid:  false,
		},
		{
			name:    "no exporters",
			configs: nil,
			hybrid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := infratelemetry.CheckRawResidency(tt.configs, tt.hybrid, tt.allowRemote)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, infratelemetry.ErrRawResidency)
			assert.Contains(t, err.Error(), "TELEMETRY_RAW_REMOTE_EXPERIMENTAL")
		})
	}
}
