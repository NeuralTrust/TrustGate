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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const testCollectorID = "11111111-1111-4111-8111-111111111111"

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name          string
		settings      map[string]any
		wantErr       bool
		wantDirection string
		wantOnError   string
	}{
		{
			name:          "valid minimal config defaults direction",
			settings:      map[string]any{"collector_id": testCollectorID},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction request accepted",
			settings:      map[string]any{"direction": directionRequest, "collector_id": testCollectorID},
			wantDirection: directionRequest,
			wantOnError:   onErrorFailOpen,
		},
		{
			// The legacy key is no longer read at all. It used to be resolved
			// ahead of direction, which silently disabled response-leg
			// inspection on any policy holding both.
			name: "legacy inspect key is ignored when direction is set",
			settings: map[string]any{
				"direction":    directionRequestResponse,
				"inspect":      directionRequest,
				"collector_id": testCollectorID,
			},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			// Nothing reads the legacy key, so a policy that stores only it
			// falls back to the default. The accompanying migration is what
			// keeps that from changing behaviour on deploy.
			name:          "legacy inspect key alone falls back to the default",
			settings:      map[string]any{"inspect": directionRequest, "collector_id": testCollectorID},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction response accepted",
			settings:      map[string]any{"direction": directionResponse, "collector_id": testCollectorID},
			wantDirection: directionResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction request_response accepted",
			settings:      map[string]any{"direction": directionRequestResponse, "collector_id": testCollectorID},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "on_error fail_closed accepted",
			settings:      map[string]any{"collector_id": testCollectorID, "on_error": onErrorFailClosed},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailClosed,
		},
		{
			name:     "invalid direction",
			settings: map[string]any{"direction": "both", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:     "invalid on_error",
			settings: map[string]any{"collector_id": testCollectorID, "on_error": "panic"},
			wantErr:  true,
		},
		{
			name:          "legacy base_url in settings ignored",
			settings:      map[string]any{"base_url": "http://guard.local", "collector_id": testCollectorID},
			wantDirection: directionRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:     "missing collector_id rejected",
			settings: map[string]any{"direction": directionRequest},
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
			assert.Equal(t, tt.wantDirection, cfg.Direction)
			assert.Equal(t, tt.wantOnError, cfg.OnError)
		})
	}
}

// TestConfigCacheKeepsDirectionsApart guards configCacheKey: it must name every
// setting parseConfig reads, or two policies differing only in one of them share
// a cache entry and the first parsed decides the resolved config for both.
func TestConfigCacheKeepsDirectionsApart(t *testing.T) {
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	set, err := p.config(map[string]any{"direction": directionRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequest, set.Direction)

	unset, err := p.config(map[string]any{"collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequestResponse, unset.Direction,
		"a policy that leaves direction unset must not inherit the cached config of one that sets it")

	again, err := p.config(map[string]any{"direction": directionRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequest, again.Direction,
		"the cached entry for an explicit direction must survive a policy that leaves it unset")
}

func TestSelectsStage(t *testing.T) {
	tests := []struct {
		name             string
		direction        string
		wantPreRequest   bool
		wantPreResponse  bool
		wantPostResponse bool
	}{
		{name: "request", direction: directionRequest, wantPreRequest: true, wantPreResponse: false, wantPostResponse: false},
		{name: "response", direction: directionResponse, wantPreRequest: false, wantPreResponse: true, wantPostResponse: true},
		{name: "request_response", direction: directionRequestResponse, wantPreRequest: true, wantPreResponse: true, wantPostResponse: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Settings{Direction: tt.direction}
			assert.Equal(t, tt.wantPreRequest, s.selectsStage(policy.StagePreRequest))
			assert.Equal(t, tt.wantPreResponse, s.selectsStage(policy.StagePreResponse))
			assert.Equal(t, tt.wantPostResponse, s.selectsStage(policy.StagePostResponse))
		})
	}
}
