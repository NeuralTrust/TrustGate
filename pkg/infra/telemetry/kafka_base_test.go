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

package telemetry

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/confluentinc/confluent-kafka-go/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyKafkaSecurity(t *testing.T) {
	t.Parallel()

	t.Run("plaintext leaves security keys unset", func(t *testing.T) {
		cm := &kafka.ConfigMap{}
		require.NoError(t, applyKafkaSecurity(cm, config.KafkaConfig{}))
		for _, key := range []string{"security.protocol", "sasl.mechanism", "sasl.username", "sasl.password", "ssl.ca.location"} {
			_, ok := (*cm)[key]
			assert.Falsef(t, ok, "expected %q to be unset for a plaintext broker", key)
		}
	})

	t.Run("sasl settings are applied", func(t *testing.T) {
		cm := &kafka.ConfigMap{}
		require.NoError(t, applyKafkaSecurity(cm, config.KafkaConfig{
			SecurityProtocol: "SASL_PLAINTEXT",
			SASLMechanism:    "SCRAM-SHA-512",
			SASLUsername:     "user",
			SASLPassword:     "pass",
			SSLCALocation:    "/etc/kafka/ssl/ca.crt",
		}))
		assert.Equal(t, "SASL_PLAINTEXT", (*cm)["security.protocol"])
		assert.Equal(t, "SCRAM-SHA-512", (*cm)["sasl.mechanism"])
		assert.Equal(t, "user", (*cm)["sasl.username"])
		assert.Equal(t, "pass", (*cm)["sasl.password"])
		assert.Equal(t, "/etc/kafka/ssl/ca.crt", (*cm)["ssl.ca.location"])
	})
}
