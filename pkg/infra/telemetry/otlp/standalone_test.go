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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/config"
)

func TestStandaloneSettings(t *testing.T) {
	t.Parallel()
	operator := config.OTLPConfig{
		Endpoint:    "http://collector:4318/v1/logs",
		Protocol:    "http/protobuf",
		Headers:     map[string]string{"authorization": "operator"},
		Timeout:     7 * time.Second,
		Insecure:    true,
		Compression: "none",
	}
	tests := []struct {
		name     string
		override config.OTLPConfig
		env      config.OTLPConfig
		want     Settings
	}{
		{
			name:     "everything from the operator",
			env: operator,
			want: Settings{
				Endpoint: "http://collector:4318/v1/logs", Protocol: ProtocolHTTP, Signal: SignalLogs,
				Headers: map[string]string{"authorization": "operator"}, Timeout: 7 * time.Second,
				Insecure: true, Compression: "none",
			},
		},
		{
			name: "own endpoint resolves its own protocol",
			override: config.OTLPConfig{
				Endpoint: "ingest.example.com:4317",
				Headers:  map[string]string{"authorization": "usage"},
				Timeout:  2 * time.Second,
			},
			env: operator,
			want: Settings{
				Endpoint: "ingest.example.com:4317", Protocol: ProtocolGRPC, Signal: SignalLogs,
				Headers: map[string]string{"authorization": "usage"}, Timeout: 2 * time.Second,
				Compression: defaultCompression, ownHeaders: true,
			},
		},
		{
			name:     "own endpoint inherits no operator headers or transport",
			override: config.OTLPConfig{Endpoint: "https://ingest.example.com/v1/logs"},
			env:      operator,
			want: Settings{
				Endpoint: "https://ingest.example.com/v1/logs", Protocol: ProtocolHTTP, Signal: SignalLogs,
				Timeout: 7 * time.Second, Compression: defaultCompression, ownHeaders: true,
			},
		},
		{
			name:     "defaults without an operator",
			override: config.OTLPConfig{Endpoint: "collector:4318"},
			want: Settings{
				Endpoint: "collector:4318", Protocol: ProtocolHTTP, Signal: SignalLogs,
				Timeout: defaultTimeout, Compression: defaultCompression, ownHeaders: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, standaloneSettings(tt.override, tt.env))
		})
	}
}

func TestNewStandaloneLogExporter(t *testing.T) {
	t.Parallel()
	_, err := NewStandaloneLogExporter(context.Background(), config.OTLPConfig{}, config.OTLPConfig{})
	require.Error(t, err)

	exporter, err := NewStandaloneLogExporter(context.Background(),
		config.OTLPConfig{Endpoint: "http://127.0.0.1:4318/v1/logs"}, config.OTLPConfig{})
	require.NoError(t, err)
	require.NoError(t, exporter.Shutdown(context.Background()))
}
