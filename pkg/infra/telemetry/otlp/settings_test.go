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

package otlp

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    map[string]interface{}
		env    config.OTLPConfig
		assert func(t *testing.T, s Settings)
	}{
		{
			name: "minimal valid applies defaults",
			raw:  map[string]interface{}{"endpoint": "collector:4318"},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, "collector:4318", s.Endpoint)
				assert.Equal(t, ProtocolHTTP, s.Protocol)
				assert.Equal(t, SignalLogs, s.Signal)
				assert.Equal(t, compressionGzip, s.Compression)
				assert.Equal(t, defaultTimeout, s.Timeout)
				assert.Equal(t, defaultMaxBodyBytes, s.MaxBodyBytes)
			},
		},
		{
			name: "unknown key tolerated",
			raw:  map[string]interface{}{"endpoint": "collector:4317", "wibble": "ignored"},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, "collector:4317", s.Endpoint)
			},
		},
		{
			name: "endpoint from env",
			raw:  map[string]interface{}{},
			env:  config.OTLPConfig{Endpoint: "env-collector:4317"},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, "env-collector:4317", s.Endpoint)
			},
		},
		{
			name: "settings override env",
			raw:  map[string]interface{}{"endpoint": "gw-collector:4317"},
			env:  config.OTLPConfig{Endpoint: "env-collector:4317"},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, "gw-collector:4317", s.Endpoint)
			},
		},
		{
			name: "protocol and compression from env",
			raw:  map[string]interface{}{"endpoint": "collector:4317"},
			env:  config.OTLPConfig{Protocol: string(ProtocolHTTP), Compression: compressionNone},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, ProtocolHTTP, s.Protocol)
				assert.Equal(t, compressionNone, s.Compression)
			},
		},
		{
			name: "timeout decoded from duration string",
			raw:  map[string]interface{}{"endpoint": "collector:4317", "timeout": "5s"},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, 5*time.Second, s.Timeout)
			},
		},
		{
			name: "insecure from env when absent in settings",
			raw:  map[string]interface{}{"endpoint": "collector:4317"},
			env:  config.OTLPConfig{Insecure: true},
			assert: func(t *testing.T, s Settings) {
				assert.True(t, s.Insecure)
			},
		},
		{
			name: "insecure setting wins over env",
			raw:  map[string]interface{}{"endpoint": "collector:4317", "insecure": false},
			env:  config.OTLPConfig{Insecure: true},
			assert: func(t *testing.T, s Settings) {
				assert.False(t, s.Insecure)
			},
		},
		{
			name: "headers from env when absent in settings",
			raw:  map[string]interface{}{"endpoint": "collector:4317"},
			env:  config.OTLPConfig{Headers: map[string]string{"authorization": "Bearer x"}},
			assert: func(t *testing.T, s Settings) {
				assert.Equal(t, "Bearer x", s.Headers["authorization"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := parseSettings(tc.raw, tc.env)
			require.NoError(t, err)
			tc.assert(t, s)
		})
	}
}

func TestParseSettingsResolvesProtocolFromEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		env      config.OTLPConfig
		want     Protocol
	}{
		{
			name:     "collector url with signal path is http",
			endpoint: "http://collector:4318/v1/logs",
			want:     ProtocolHTTP,
		},
		{
			name:     "scheme-less endpoint with path is http",
			endpoint: "collector:4318/v1/logs",
			want:     ProtocolHTTP,
		},
		{
			name:     "otlp http port without path is http",
			endpoint: "http://collector:4318",
			want:     ProtocolHTTP,
		},
		{
			name:     "otlp grpc port is grpc",
			endpoint: "collector:4317",
			want:     ProtocolGRPC,
		},
		{
			name:     "unknown port falls back to the default",
			endpoint: "collector:9999",
			want:     defaultProtocol,
		},
		{
			name:     "env protocol wins over the endpoint",
			endpoint: "http://collector:4318/v1/logs",
			env:      config.OTLPConfig{Protocol: string(ProtocolGRPC)},
			want:     ProtocolGRPC,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := parseSettings(map[string]interface{}{"endpoint": tc.endpoint}, tc.env)
			require.NoError(t, err)
			assert.Equal(t, tc.want, s.Protocol)
		})
	}
}

func TestWithLogsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "endpoint without path gets the signal path",
			endpoint: "http://collector:4318",
			want:     "http://collector:4318/v1/logs",
		},
		{
			name:     "trailing slash is not doubled",
			endpoint: "http://collector:4318/",
			want:     "http://collector:4318/v1/logs",
		},
		{
			name:     "existing signal path is kept",
			endpoint: "http://collector:4318/v1/logs",
			want:     "http://collector:4318/v1/logs",
		},
		{
			name:     "custom path is kept",
			endpoint: "https://gateway.example.com/otlp/v1/logs",
			want:     "https://gateway.example.com/otlp/v1/logs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, withLogsPath(tc.endpoint))
		})
	}
}

func TestSettingsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     map[string]interface{}
		env     config.OTLPConfig
		wantErr string
	}{
		{
			name:    "missing endpoint without env fallback",
			raw:     map[string]interface{}{},
			wantErr: "endpoint",
		},
		{
			name:    "invalid protocol enum",
			raw:     map[string]interface{}{"endpoint": "collector:4317", "protocol": "tcp"},
			wantErr: "protocol",
		},
		{
			name:    "invalid signal enum",
			raw:     map[string]interface{}{"endpoint": "collector:4317", "signal": "metrics"},
			wantErr: "signal",
		},
		{
			name:    "traces signal reserved",
			raw:     map[string]interface{}{"endpoint": "collector:4317", "signal": "traces"},
			wantErr: "reserved",
		},
		{
			name:    "non-positive timeout",
			raw:     map[string]interface{}{"endpoint": "collector:4317", "timeout": "-1s"},
			wantErr: "timeout",
		},
		{
			name: "grpc endpoint carrying a path",
			raw: map[string]interface{}{
				"endpoint": "http://collector:4317/v1/logs",
				"protocol": string(ProtocolGRPC),
			},
			wantErr: "must not carry a path",
		},
		{
			name:    "invalid compression",
			raw:     map[string]interface{}{"endpoint": "collector:4317", "compression": "snappy"},
			wantErr: "compression",
		},
		{
			name: "insecure combined with tls",
			raw: map[string]interface{}{
				"endpoint": "collector:4317",
				"insecure": true,
				"tls":      map[string]interface{}{"ca_file": "/does/not/exist/ca.pem"},
			},
			wantErr: "insecure",
		},
		{
			name: "missing tls file",
			raw: map[string]interface{}{
				"endpoint": "collector:4317",
				"tls":      map[string]interface{}{"ca_file": "/does/not/exist/ca.pem"},
			},
			wantErr: "tls file",
		},
		{
			name: "tls cert without key",
			raw: map[string]interface{}{
				"endpoint": "collector:4317",
				"tls":      map[string]interface{}{"cert_file": "/does/not/exist/cert.pem"},
			},
			wantErr: "together",
		},
		{
			name: "tls key without cert",
			raw: map[string]interface{}{
				"endpoint": "collector:4317",
				"tls":      map[string]interface{}{"key_file": "/does/not/exist/key.pem"},
			},
			wantErr: "together",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := parseSettings(tc.raw, tc.env)
			require.NoError(t, err)
			err = s.validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestSettingsValidate_Valid(t *testing.T) {
	t.Parallel()

	s, err := parseSettings(map[string]interface{}{"endpoint": "collector:4317"}, config.OTLPConfig{})
	require.NoError(t, err)
	require.NoError(t, s.validate())
}
