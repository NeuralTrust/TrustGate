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
		name        string
		settings    map[string]any
		wantErr     bool
		wantInspect string
		wantOnError string
	}{
		{
			name:        "valid minimal config defaults inspect",
			settings:    map[string]any{"collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
			wantOnError: onErrorFailOpen,
		},
		{
			name:        "inspect request accepted",
			settings:    map[string]any{"inspect": inspectRequest, "collector_id": testCollectorID},
			wantInspect: inspectRequest,
			wantOnError: onErrorFailOpen,
		},
		{
			name:        "catalog direction alias maps to inspect",
			settings:    map[string]any{"direction": inspectRequest, "collector_id": testCollectorID},
			wantInspect: inspectRequest,
			wantOnError: onErrorFailOpen,
		},
		{
			name:        "inspect response accepted",
			settings:    map[string]any{"inspect": inspectResponse, "collector_id": testCollectorID},
			wantInspect: inspectResponse,
			wantOnError: onErrorFailOpen,
		},
		{
			name:        "inspect request_response accepted",
			settings:    map[string]any{"inspect": inspectRequestResponse, "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
			wantOnError: onErrorFailOpen,
		},
		{
			name:        "on_error fail_closed accepted",
			settings:    map[string]any{"collector_id": testCollectorID, "on_error": onErrorFailClosed},
			wantInspect: inspectRequestResponse,
			wantOnError: onErrorFailClosed,
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
			name:        "legacy base_url in settings ignored",
			settings:    map[string]any{"base_url": "http://guard.local", "collector_id": testCollectorID},
			wantInspect: inspectRequestResponse,
			wantOnError: onErrorFailOpen,
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
			assert.Equal(t, tt.wantOnError, cfg.OnError)
		})
	}
}

func TestConfigCacheKeepsDirectionAndInspectApart(t *testing.T) {
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	legacy, err := p.config(context.Background(), map[string]any{"direction": inspectRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, inspectRequest, legacy.Inspect)

	unset, err := p.config(context.Background(), map[string]any{"collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, inspectRequestResponse, unset.Inspect,
		"a policy that sets neither key must not inherit the cached config of one that sets direction")

	again, err := p.config(context.Background(), map[string]any{"direction": inspectRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, inspectRequest, again.Inspect,
		"the cached entry for direction must survive a policy that leaves it unset")
}

func TestSelectsStage(t *testing.T) {
	tests := []struct {
		name             string
		inspect          string
		wantPreRequest   bool
		wantPreResponse  bool
		wantPostResponse bool
	}{
		{name: "request", inspect: inspectRequest, wantPreRequest: true, wantPreResponse: false, wantPostResponse: false},
		{name: "response", inspect: inspectResponse, wantPreRequest: false, wantPreResponse: true, wantPostResponse: true},
		{name: "request_response", inspect: inspectRequestResponse, wantPreRequest: true, wantPreResponse: true, wantPostResponse: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Settings{Inspect: tt.inspect}
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
		"direction":    inspectRequestResponse,
		"inspect":      inspectRequest,
	})
	require.NoError(t, err)
	assert.Equal(t, inspectRequestResponse, cfg.Inspect,
		"direction is the operator-visible key and must win over a stale inspect")
	assert.True(t, cfg.selectsStage(policy.StagePreResponse),
		"the response leg must be inspected when direction says request_response")
}

// TestParseConfigInspectAloneStillHonoured keeps the older key working for
// policies provisioned before the catalog settled on direction.
func TestParseConfigInspectAloneStillHonoured(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"inspect":      inspectRequest,
	})
	require.NoError(t, err)
	assert.Equal(t, inspectRequest, cfg.Inspect)
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
			settings:     map[string]any{"direction": inspectRequestResponse, "inspect": inspectRequest},
			wantDisagree: true,
		},
		{
			name:         "both set and equal",
			settings:     map[string]any{"direction": inspectRequest, "inspect": inspectRequest},
			wantDisagree: false,
		},
		{
			name:         "only direction",
			settings:     map[string]any{"direction": inspectRequestResponse},
			wantDisagree: false,
		},
		{
			name:         "only inspect",
			settings:     map[string]any{"inspect": inspectRequest},
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
