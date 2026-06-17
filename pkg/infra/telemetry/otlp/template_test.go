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

package otlp_test

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/otlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplate_BuildsRealExporterThroughLocator(t *testing.T) {
	t.Parallel()
	locator := infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(nil, config.OTLPConfig{})),
	)

	cfg := telemetrydomain.ExporterConfig{
		Name:     otlp.ExporterName,
		Settings: map[string]interface{}{"endpoint": "collector:4317", "insecure": true},
	}

	require.NoError(t, locator.Validate(cfg))

	exporter, err := locator.Build(cfg)
	require.NoError(t, err)
	require.NotNil(t, exporter)
	t.Cleanup(exporter.Close)

	assert.Equal(t, otlp.ExporterName, exporter.Name())
}

func TestTemplate_LocatorPropagatesValidationError(t *testing.T) {
	t.Parallel()
	locator := infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(nil, config.OTLPConfig{})),
	)

	err := locator.Validate(telemetrydomain.ExporterConfig{
		Name:     otlp.ExporterName,
		Settings: map[string]interface{}{"endpoint": "collector:4317", "protocol": "tcp"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "otlp")
	assert.Contains(t, err.Error(), "protocol")
}

func TestTemplate_EnvFallbackBuildsWithoutPerGatewayEndpoint(t *testing.T) {
	t.Parallel()
	locator := infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(nil, config.OTLPConfig{
			Endpoint: "env-collector:4317",
			Insecure: true,
		})),
	)

	cfg := telemetrydomain.ExporterConfig{Name: otlp.ExporterName, Settings: map[string]interface{}{}}

	require.NoError(t, locator.Validate(cfg))

	exporter, err := locator.Build(cfg)
	require.NoError(t, err)
	require.NotNil(t, exporter)
	t.Cleanup(exporter.Close)
}
