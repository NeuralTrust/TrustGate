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

package modules

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeExporter struct {
	name string
}

func (f *fakeExporter) Name() string                                 { return f.name }
func (f *fakeExporter) Publish(context.Context, *events.Event) error { return nil }
func (f *fakeExporter) Close()                                       {}

func TestNewDefaultExporters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		write   bool
		content string
		setup   func(factory *mocks.ExporterFactory)
		assert  func(t *testing.T, exporters []appmetrics.Exporter, err error)
	}{
		{
			name:  "valid entries are built in file order",
			write: true,
			content: `exporters:
  - name: otlp
    type: otlp
  - name: kafka
    type: kafka
`,
			setup: func(factory *mocks.ExporterFactory) {
				factory.EXPECT().Validate(mock.Anything).Return(nil)
				factory.EXPECT().Build(mock.Anything).RunAndReturn(
					func(cfg telemetrydomain.ExporterConfig) (appmetrics.Exporter, error) {
						return &fakeExporter{name: cfg.Name}, nil
					})
			},
			assert: func(t *testing.T, exporters []appmetrics.Exporter, err error) {
				require.NoError(t, err)
				require.Len(t, exporters, 2)
				assert.Equal(t, []string{"otlp", "kafka"}, []string{exporters[0].Name(), exporters[1].Name()})
			},
		},
		{
			name:  "entry failing validation aborts boot naming the entry",
			write: true,
			content: `exporters:
  - name: brokenexporter
    type: brokenexporter
`,
			setup: func(factory *mocks.ExporterFactory) {
				factory.EXPECT().Validate(mock.Anything).Return(errors.New("invalid settings"))
			},
			assert: func(t *testing.T, exporters []appmetrics.Exporter, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "brokenexporter")
				assert.Nil(t, exporters)
			},
		},
		{
			name:  "build failure aborts boot naming the entry",
			write: true,
			content: `exporters:
  - name: otlp
    type: otlp
`,
			setup: func(factory *mocks.ExporterFactory) {
				factory.EXPECT().Validate(mock.Anything).Return(nil)
				factory.EXPECT().Build(mock.Anything).Return(nil, errors.New("dial failed"))
			},
			assert: func(t *testing.T, exporters []appmetrics.Exporter, err error) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "otlp")
				assert.Nil(t, exporters)
			},
		},
		{
			name:  "missing file yields no defaults and no error",
			write: false,
			setup: func(factory *mocks.ExporterFactory) {},
			assert: func(t *testing.T, exporters []appmetrics.Exporter, err error) {
				require.NoError(t, err)
				assert.Empty(t, exporters)
			},
		},
		{
			name:    "empty file yields no defaults and no error",
			write:   true,
			content: "",
			setup:   func(factory *mocks.ExporterFactory) {},
			assert: func(t *testing.T, exporters []appmetrics.Exporter, err error) {
				require.NoError(t, err)
				assert.Empty(t, exporters)
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

			factory := mocks.NewExporterFactory(t)
			tt.setup(factory)

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			exporters, err := newDefaultExporters(logger, factory, path)
			tt.assert(t, exporters, err)
		})
	}
}
