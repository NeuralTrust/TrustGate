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

	"github.com/NeuralTrust/TrustGate/pkg/common/valuecopy"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/postgres"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The settings map an exporter template receives is not the template's to keep.
// It arrives by reference from the gateway cache — gatewayExporters returns
// gw.Telemetry.Exporters with no copy — is captured by the metrics middleware
// closures, and is carried onto the worker pool, which marshals the config on
// every request to build the exporter cache key (app/metrics/exporter_cache.go).
//
// Under Go 1.27 that marshal walks a map twice: encoding/json/v2 collects the
// keys, sorts them, and looks each value up again with reflect.MapIndex, so a
// key gone by the second pass yields the zero Value and reflect.Value.Set
// panics. A template that wrote into the map it was handed would therefore turn
// an ordinary config read into an intermittent, process-wide crash — the same
// failure RUN-1261 chased in the telemetry event.
//
// The RUN-1263 audit found no such write in either repository, and the maps are
// otherwise only read, so nothing needs copying on the request path. That makes
// read-only treatment the invariant the safety rests on rather than a
// coincidence, and this test is what holds it. TrustGuard carries the twin of
// this file at internal/infra/telemetry/settings_readonly_test.go; the two
// repositories share this shape and are kept in step deliberately.
func TestExporterTemplates_TreatSettingsAsReadOnly(t *testing.T) {
	t.Parallel()

	// ValidateConfig is the entry point under test rather than WithSettings,
	// because in every template both route the settings map through the same
	// decode — ResolveBaseConfig for kafka, parseSettings for the others — and
	// WithSettings goes on to dial a broker or open a pool.
	cases := []struct {
		name     string
		settings map[string]any
		validate func(settings map[string]any) error
	}{
		{
			name: "kafka",
			settings: map[string]any{
				"topic":   "events",
				"brokers": []any{"localhost:9092"},
			},
			validate: func(settings map[string]any) error {
				template := kafka.NewKafkaTemplate(testLogger(), config.KafkaConfig{
					Brokers: []string{"localhost:9092"},
				})
				return template.ValidateConfig(settings)
			},
		},
		{
			name: "otlp",
			settings: map[string]any{
				"endpoint":    "otel.invalid:4317",
				"protocol":    "grpc",
				"signal":      "logs",
				"insecure":    true,
				"timeout":     "5s",
				"compression": "gzip",
				"headers": map[string]any{
					"authorization": "Bearer token",
				},
			},
			validate: func(settings map[string]any) error {
				return otlp.NewTemplate(testLogger(), config.OTLPConfig{}).ValidateConfig(settings)
			},
		},
		{
			name: "postgres",
			settings: map[string]any{
				"dsn":   "postgres://user:pass@localhost:5432/trustgate",
				"table": metricsschema.TableName,
			},
			validate: func(settings map[string]any) error {
				return postgres.NewTemplate(testLogger(), &config.DatabaseConfig{
					Host: "localhost", Port: 5432, User: "test", Name: "test", SSLMode: "disable",
				}).ValidateConfig(settings)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := valuecopy.Deep(tc.settings)
			require.NoError(t, tc.validate(tc.settings))
			assert.Equal(t, before, any(tc.settings),
				"template mutated the settings it was given; they are shared by reference with every request goroutine")
		})
	}
}

// A template reached through the locator must be just as hands-off, since that
// is the path the metrics pipeline actually takes to resolve an exporter.
func TestExporterLocator_ValidateTreatsSettingsAsReadOnly(t *testing.T) {
	t.Parallel()

	cfg := telemetrydomain.ExporterConfig{
		Name: kafka.ExporterName,
		Settings: map[string]any{
			"topic":   "events",
			"brokers": []any{"localhost:9092"},
			"nested": map[string]any{
				"retries": 3,
			},
		},
	}
	before := valuecopy.Deep(cfg.Settings)

	require.NoError(t, newLocator().Validate(cfg))
	assert.Equal(t, before, any(cfg.Settings),
		"the locator's validate path mutated the exporter settings")
}
