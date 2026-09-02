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
	"context"
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
			settings:      map[string]any{"inspect": directionRequest, "collector_id": testCollectorID},
			wantDirection: directionRequest,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "legacy inspect key normalizes into direction",
			settings:      map[string]any{"direction": directionRequest, "collector_id": testCollectorID},
			wantDirection: directionRequest,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction response accepted",
			settings:      map[string]any{"inspect": directionResponse, "collector_id": testCollectorID},
			wantDirection: directionResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction request_response accepted",
			settings:      map[string]any{"inspect": directionRequestResponse, "collector_id": testCollectorID},
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
			name:     "invalid inspect",
			settings: map[string]any{"inspect": "both", "collector_id": testCollectorID},
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
			settings: map[string]any{"inspect": directionRequest},
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

func TestConfigCacheKeepsDirectionAndInspectApart(t *testing.T) {
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	legacy, err := p.config(context.Background(), map[string]any{"direction": directionRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequest, legacy.Direction)

	unset, err := p.config(context.Background(), map[string]any{"collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequestResponse, unset.Direction,
		"a policy that sets neither key must not inherit the cached config of one that sets direction")

	again, err := p.config(context.Background(), map[string]any{"direction": directionRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, directionRequest, again.Direction,
		"the cached entry for direction must survive a policy that leaves it unset")
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

// TestParseConfigDirectionWinsOverStaleInspect pins the precedence that a
// production policy depended on and did not get. Its settings carried
// direction=request_response — what the catalog declares and the console form
// edits — next to a stale inspect=request. The old precedence let the invisible
// key win, so pre_response returned early, no evaluate ever reached the guard on
// the response leg, and DLP rules bound to the output direction never saw a tool
// result while the console still showed "Request & Response".
func TestParseConfigDirectionWinsOverStaleInspect(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"direction":    directionRequestResponse,
		"inspect":      directionRequest,
	})
	require.NoError(t, err)
	assert.Equal(t, directionRequestResponse, cfg.Direction,
		"direction is the operator-visible key and must win over a stale inspect")
	assert.True(t, cfg.selectsStage(policy.StagePreResponse),
		"the response leg must be inspected when direction says request_response")
}

// TestParseConfigInspectAloneStillHonoured keeps the older key working for
// policies provisioned before the catalog settled on direction.
func TestParseConfigInspectAloneStillHonoured(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"inspect":      directionRequest,
	})
	require.NoError(t, err)
	assert.Equal(t, directionRequest, cfg.Direction)
	assert.False(t, cfg.selectsStage(policy.StagePreResponse))
}

func TestLegKeysDisagree(t *testing.T) {
	tests := []struct {
		name         string
		settings     map[string]any
		wantDisagree bool
	}{
		{
			name:         "both set and different",
			settings:     map[string]any{"direction": directionRequestResponse, "inspect": directionRequest},
			wantDisagree: true,
		},
		{
			name:         "both set and equal",
			settings:     map[string]any{"direction": directionRequest, "inspect": directionRequest},
			wantDisagree: false,
		},
		{
			name:         "only direction",
			settings:     map[string]any{"direction": directionRequestResponse},
			wantDisagree: false,
		},
		{
			name:         "only inspect",
			settings:     map[string]any{"inspect": directionRequest},
			wantDisagree: false,
		},
		{
			name:         "neither",
			settings:     map[string]any{"collector_id": testCollectorID},
			wantDisagree: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, disagree := legKeysDisagree(tt.settings)
			assert.Equal(t, tt.wantDisagree, disagree)
		})
	}
}
