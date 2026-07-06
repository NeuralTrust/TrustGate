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

package exportersfile_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/exportersfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		write   bool
		assert  func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error)
	}{
		{
			name:  "valid single otlp",
			write: true,
			content: `exporters:
  - name: otlp
    type: otlp
    settings:
      endpoint: "otel-collector:4317"
      protocol: "grpc"
`,
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				require.Len(t, configs, 1)
				assert.Equal(t, "otlp", configs[0].Name)
				assert.Equal(t, "otlp", configs[0].Type)
				assert.Equal(t, "otel-collector:4317", configs[0].Settings["endpoint"])
				assert.Equal(t, "grpc", configs[0].Settings["protocol"])
			},
		},
		{
			name:  "valid multiple preserves order",
			write: true,
			content: `exporters:
  - name: first
    type: otlp
  - name: second
    type: kafka
  - name: third
    type: postgres
`,
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				require.Len(t, configs, 3)
				assert.Equal(t, []string{"first", "second", "third"}, []string{configs[0].Name, configs[1].Name, configs[2].Name})
				assert.Equal(t, []string{"otlp", "kafka", "postgres"}, []string{configs[0].Type, configs[1].Type, configs[2].Type})
			},
		},
		{
			name:  "missing file returns ErrFileNotFound",
			write: false,
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.Error(t, err)
				assert.True(t, errors.Is(err, exportersfile.ErrFileNotFound))
				assert.Nil(t, configs)
			},
		},
		{
			name:    "empty file returns no entries",
			write:   true,
			content: "",
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				assert.Empty(t, configs)
			},
		},
		{
			name:    "exporters key absent returns no entries",
			write:   true,
			content: "other: 1\n",
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				assert.Empty(t, configs)
			},
		},
		{
			name:    "empty exporters list returns no entries",
			write:   true,
			content: "exporters: []\n",
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				assert.Empty(t, configs)
			},
		},
		{
			name:    "malformed yaml returns error not ErrFileNotFound",
			write:   true,
			content: "exporters: [ {",
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.Error(t, err)
				assert.False(t, errors.Is(err, exportersfile.ErrFileNotFound))
				assert.Nil(t, configs)
			},
		},
		{
			name:  "unknown type still parses",
			write: true,
			content: `exporters:
  - name: sink
    type: datadog
`,
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				require.Len(t, configs, 1)
				assert.Equal(t, "sink", configs[0].Name)
				assert.Equal(t, "datadog", configs[0].Type)
			},
		},
		{
			name:  "type omitted keeps empty type and name",
			write: true,
			content: `exporters:
  - name: kafka
`,
			assert: func(t *testing.T, configs []telemetrydomain.ExporterConfig, err error) {
				require.NoError(t, err)
				require.Len(t, configs, 1)
				assert.Equal(t, "kafka", configs[0].Name)
				assert.Equal(t, "", configs[0].Type)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "telemetry.yaml")
			if tt.write {
				require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			}

			configs, err := exportersfile.Load(path)
			tt.assert(t, configs, err)
		})
	}
}
