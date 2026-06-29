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

package trustguard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

const testCollectorID = "11111111-1111-4111-8111-111111111111"

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name        string
		settings    map[string]any
		wantErr     bool
		wantInspect string
	}{
		{
			name:        "valid minimal config defaults inspect",
			settings:    map[string]any{"collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
		},
		{
			name:        "inspect request accepted",
			settings:    map[string]any{"inspect": inspectRequest, "collector_id": testCollectorID},
			wantInspect: inspectRequest,
		},
		{
			name:        "catalog direction alias maps to inspect",
			settings:    map[string]any{"direction": inspectRequest, "collector_id": testCollectorID},
			wantInspect: inspectRequest,
		},
		{
			name:        "inspect response accepted",
			settings:    map[string]any{"inspect": inspectResponse, "collector_id": testCollectorID},
			wantInspect: inspectResponse,
		},
		{
			name:        "inspect request_response accepted",
			settings:    map[string]any{"inspect": inspectRequestResponse, "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
		},
		{
			name:     "invalid inspect",
			settings: map[string]any{"inspect": "both", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:        "base_url http accepted",
			settings:    map[string]any{"base_url": "http://guard.local", "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
		},
		{
			name:        "base_url https accepted",
			settings:    map[string]any{"base_url": "https://guard.example.com/api", "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
		},
		{
			name:        "empty base_url ok",
			settings:    map[string]any{"base_url": "", "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
		},
		{
			name:     "base_url relative rejected",
			settings: map[string]any{"base_url": "/v1/guard", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:     "base_url missing scheme rejected",
			settings: map[string]any{"base_url": "guard.local", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:     "base_url non-http scheme rejected",
			settings: map[string]any{"base_url": "ftp://guard.local", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:     "base_url missing host rejected",
			settings: map[string]any{"base_url": "http://", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:     "missing collector_id rejected",
			settings: map[string]any{"inspect": inspectRequest},
			wantErr:  true,
		},
		{
			name:     "invalid collector_id rejected",
			settings: map[string]any{"collector_id": "not-a-uuid"},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantInspect, cfg.Inspect)
		})
	}
}

func TestSelectsStage(t *testing.T) {
	tests := []struct {
		name            string
		inspect         string
		wantPreRequest  bool
		wantPreResponse bool
	}{
		{name: "request", inspect: inspectRequest, wantPreRequest: true, wantPreResponse: false},
		{name: "response", inspect: inspectResponse, wantPreRequest: false, wantPreResponse: true},
		{name: "request_response", inspect: inspectRequestResponse, wantPreRequest: true, wantPreResponse: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Settings{Inspect: tt.inspect}
			assert.Equal(t, tt.wantPreRequest, s.selectsStage(policy.StagePreRequest))
			assert.Equal(t, tt.wantPreResponse, s.selectsStage(policy.StagePreResponse))
		})
	}
}
