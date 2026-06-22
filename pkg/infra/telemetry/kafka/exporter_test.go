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

package kafka_test

import (
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestKafkaTemplate_ValidateConfig(t *testing.T) {
	t.Parallel()

	withEnvBrokers := kafka.NewKafkaTemplate(testLogger(), config.KafkaConfig{Brokers: []string{"localhost:9092"}})
	noBrokers := kafka.NewKafkaTemplate(testLogger(), config.KafkaConfig{})

	t.Run("topic required", func(t *testing.T) {
		err := withEnvBrokers.ValidateConfig(map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "topic")
	})

	t.Run("brokers fall back to env", func(t *testing.T) {
		err := withEnvBrokers.ValidateConfig(map[string]interface{}{"topic": "events"})
		require.NoError(t, err)
	})

	t.Run("brokers required when env empty", func(t *testing.T) {
		err := noBrokers.ValidateConfig(map[string]interface{}{"topic": "events"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "brokers")
	})

	t.Run("explicit brokers satisfy validation", func(t *testing.T) {
		err := noBrokers.ValidateConfig(map[string]interface{}{
			"topic":   "events",
			"brokers": []string{"broker:9092"},
		})
		require.NoError(t, err)
	})
}
