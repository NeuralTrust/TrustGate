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
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newLocator() *infratelemetry.ExporterLocator {
	return infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaTemplate(testLogger(), config.KafkaConfig{Brokers: []string{"localhost:9092"}})),
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

	t.Run("invalid data class", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: kafka.ExporterName, Class: "bogus", Settings: map[string]interface{}{"topic": "events"}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data class")
	})

	t.Run("valid kafka config", func(t *testing.T) {
		err := locator.Validate(telemetrydomain.ExporterConfig{Name: kafka.ExporterName, Settings: map[string]interface{}{"topic": "events"}})
		require.NoError(t, err)
	})
}

func TestExporterLocator_BuildUnknownExporter(t *testing.T) {
	t.Parallel()
	locator := newLocator()

	exporter, err := locator.Build(telemetrydomain.ExporterConfig{Name: "datadog"})
	require.Error(t, err)
	assert.Nil(t, exporter)
}
