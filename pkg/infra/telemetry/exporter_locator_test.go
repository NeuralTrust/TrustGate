package telemetry_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/kafka"
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
