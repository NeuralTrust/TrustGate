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

package o11y

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func telemetryConfig(tel config.TelemetryConfig) *config.Config {
	return &config.Config{AppEnv: "test", Telemetry: tel}
}

func TestNewSDKDisabledInstallsNothing(t *testing.T) {
	sdk, err := NewSDK(telemetryConfig(config.TelemetryConfig{}), testLogger())
	require.NoError(t, err)
	require.Nil(t, sdk.Tracer())
	require.NoError(t, sdk.Shutdown(context.Background()))
}

// Enabling a signal without its endpoint must fail at boot. Starting anyway is
// how a gateway ends up exporting nothing while looking healthy (AUT-576).
func TestNewSDKRejectsTracesWithoutEndpoint(t *testing.T) {
	_, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsTracesEnabled: true,
	}), testLogger())
	require.ErrorContains(t, err, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

func TestNewSDKRejectsMetricsWithoutEndpoint(t *testing.T) {
	_, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsMetricsEnabled: true,
	}), testLogger())
	require.ErrorContains(t, err, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
}

func TestNewSDKTracesProvideTracer(t *testing.T) {
	sdk, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsTracesEnabled: true,
		OTLP:             config.OTLPConfig{TracesEndpoint: "collector.svc:4318"},
	}), testLogger())
	require.NoError(t, err)
	require.NotNil(t, sdk.Tracer())
	require.NoError(t, sdk.Shutdown(context.Background()))
}

func TestSignalEndpointAddsSignalPath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "bare authority", raw: "collector.svc:4318", want: "http://collector.svc:4318/v1/traces"},
		{name: "scheme only", raw: "https://collector.svc:4318", want: "https://collector.svc:4318/v1/traces"},
		{name: "trailing slash", raw: "http://collector.svc:4318/", want: "http://collector.svc:4318/v1/traces"},
		{name: "explicit path kept", raw: "http://collector.svc:4318/otlp/v1/traces", want: "http://collector.svc:4318/otlp/v1/traces"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signalEndpoint(tc.raw, tracesSignalPath, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSamplingRatioClampsOutOfRange(t *testing.T) {
	require.InDelta(t, 1.0, samplingRatio(0), 0)
	require.InDelta(t, 1.0, samplingRatio(-0.5), 0)
	require.InDelta(t, 1.0, samplingRatio(2), 0)
	require.InDelta(t, 0.25, samplingRatio(0.25), 0)
}

func TestResourceIdentifiesTheGateway(t *testing.T) {
	attrs := map[string]string{}
	for _, kv := range newResource(telemetryConfig(config.TelemetryConfig{})).Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	require.Equal(t, ServiceName, attrs["service.name"])
	require.Equal(t, ServiceName, attrs[gatewayAttribute])
	require.Equal(t, "test", attrs["deployment.environment.name"])
}
