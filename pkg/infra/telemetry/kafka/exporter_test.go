package kafka_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newExporter(brokers ...string) *kafka.Exporter {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return kafka.NewKafkaExporter(logger, config.KafkaConfig{Brokers: brokers})
}

func TestExporter_Name(t *testing.T) {
	assert.Equal(t, "kafka", newExporter("localhost:9092").Name())
}

func TestExporter_ValidateConfig(t *testing.T) {
	t.Run("missing brokers", func(t *testing.T) {
		exp := newExporter()
		err := exp.ValidateConfig(map[string]interface{}{"topic": "events"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "brokers")
	})

	t.Run("missing topic", func(t *testing.T) {
		exp := newExporter("localhost:9092")
		err := exp.ValidateConfig(map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "topic")
	})

	t.Run("valid with env brokers and settings topic", func(t *testing.T) {
		exp := newExporter("localhost:9092")
		assert.NoError(t, exp.ValidateConfig(map[string]interface{}{"topic": "events"}))
	})

	t.Run("valid with settings brokers override", func(t *testing.T) {
		exp := newExporter()
		settings := map[string]interface{}{
			"brokers": []string{"broker-1:9092"},
			"topic":   "events",
		}
		assert.NoError(t, exp.ValidateConfig(settings))
	})
}
