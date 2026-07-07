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
	"context"
	"io"
	"log/slog"
	"testing"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/postgres"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type classAwareExporter struct {
	class    metricsschema.DataClass
	setCalls int
}

func (e *classAwareExporter) Name() string                                 { return "fake" }
func (e *classAwareExporter) DataClass() metricsschema.DataClass           { return e.class }
func (e *classAwareExporter) Publish(context.Context, *events.Event) error { return nil }
func (e *classAwareExporter) Close()                                       {}
func (e *classAwareExporter) SetDataClass(c metricsschema.DataClass) {
	e.class = c
	e.setCalls++
}

type classAwareTemplate struct{ exp *classAwareExporter }

func (t *classAwareTemplate) Name() string                                { return "fake" }
func (t *classAwareTemplate) ValidateConfig(map[string]interface{}) error { return nil }
func (t *classAwareTemplate) WithSettings(map[string]interface{}) (appmetrics.Exporter, error) {
	return t.exp, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newLocator() *infratelemetry.ExporterLocator {
	return infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaTemplate(testLogger(), config.KafkaConfig{Brokers: []string{"localhost:9092"}})),
		infratelemetry.WithExporter(postgres.ExporterName, postgres.NewTemplate(testLogger())),
	)
}

func TestExporterLocator_Validate(t *testing.T) {
	t.Parallel()
	locator := newLocator()

	t.Run("unknown exporter", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: "datadog"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown exporter")
	})

	t.Run("missing topic", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: kafka.ExporterName, Settings: map[string]interface{}{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "topic")
	})

	t.Run("valid kafka config", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: kafka.ExporterName, Settings: map[string]interface{}{"topic": "events"}})
		require.NoError(t, err)
	})

	t.Run("postgres resolved through the optional type field", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{
			Name: "sensible-pg",
			Type: postgres.ExporterName,
			Settings: map[string]interface{}{
				"dsn": "postgres://user:pass@localhost:5432/telemetry?sslmode=disable",
			},
		})
		require.NoError(t, err)
	})

	t.Run("postgres without a dsn is rejected", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: postgres.ExporterName, Settings: map[string]interface{}{}})
		require.Error(t, err)
	})
}

func TestExporterLocator_BuildUnknownExporter(t *testing.T) {
	t.Parallel()
	locator := newLocator()

	exporter, err := locator.Build(telemetrydomain.ExporterConfig{Name: "datadog"})
	require.Error(t, err)
	assert.Nil(t, exporter)
}

func TestExporterLocator_BuildInjectsDeclaredClass(t *testing.T) {
	t.Parallel()

	t.Run("declared class is injected into class-aware exporters", func(t *testing.T) {
		exp := &classAwareExporter{}
		locator := infratelemetry.NewExporterLocator(infratelemetry.WithExporter("fake", &classAwareTemplate{exp: exp}))

		_, err := locator.Build(telemetrydomain.ExporterConfig{Name: "fake", Class: metricsschema.Raw})
		require.NoError(t, err)
		assert.Equal(t, metricsschema.Raw, exp.DataClass())
		assert.Equal(t, 1, exp.setCalls)
	})

	t.Run("empty class leaves the exporter untouched", func(t *testing.T) {
		exp := &classAwareExporter{class: metricsschema.Metadata}
		locator := infratelemetry.NewExporterLocator(infratelemetry.WithExporter("fake", &classAwareTemplate{exp: exp}))

		_, err := locator.Build(telemetrydomain.ExporterConfig{Name: "fake"})
		require.NoError(t, err)
		assert.Equal(t, metricsschema.Metadata, exp.DataClass())
		assert.Equal(t, 0, exp.setCalls)
	})
}
