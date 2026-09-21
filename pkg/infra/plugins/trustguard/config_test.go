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
			wantDirection: legRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction request accepted",
			settings:      map[string]any{"direction": legRequest, "collector_id": testCollectorID},
			wantDirection: legRequest,
			wantOnError:   onErrorFailOpen,
		},
		{
			// The legacy key is no longer read at all. It used to be resolved
			// ahead of direction, which silently disabled response-leg
			// inspection on any policy holding both.
			name: "legacy inspect key is ignored when direction is set",
			settings: map[string]any{
				"direction":    legRequestResponse,
				"inspect":      legRequest,
				"collector_id": testCollectorID,
			},
			wantDirection: legRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			// Nothing reads the legacy key, so a policy that stores only it
			// falls back to the default. The accompanying migration is what
			// keeps that from changing behaviour on deploy.
			name:          "legacy inspect key alone falls back to the default",
			settings:      map[string]any{"inspect": legRequest, "collector_id": testCollectorID},
			wantDirection: legRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction response accepted",
			settings:      map[string]any{"direction": legResponse, "collector_id": testCollectorID},
			wantDirection: legResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "direction request_response accepted",
			settings:      map[string]any{"direction": legRequestResponse, "collector_id": testCollectorID},
			wantDirection: legRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:          "on_error fail_closed accepted",
			settings:      map[string]any{"collector_id": testCollectorID, "on_error": onErrorFailClosed},
			wantDirection: legRequestResponse,
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
			wantDirection: legRequestResponse,
			wantOnError:   onErrorFailOpen,
		},
		{
			name:     "missing collector_id rejected",
			settings: map[string]any{"direction": legRequest},
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

// TestConfigCacheKeepsDirectionsApart guards the configCacheKey invariant: two
// policies differing in any setting must not share a cache entry, or the first
// one parsed decides the resolved config for both.
func TestConfigCacheKeepsDirectionsApart(t *testing.T) {
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	set, err := p.config(map[string]any{"direction": legRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, legRequest, set.Direction)

	unset, err := p.config(map[string]any{"collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, legRequestResponse, unset.Direction,
		"a policy that leaves direction unset must not inherit the cached config of one that sets it")

	again, err := p.config(map[string]any{"direction": legRequest, "collector_id": testCollectorID})
	require.NoError(t, err)
	assert.Equal(t, legRequest, again.Direction,
		"the cached entry for an explicit direction must survive a policy that leaves it unset")
}

// TestConfigCacheSeesEditsToAnySetting is the regression for the cache trap:
// configCacheKey used to name direction, collector_id and on_error only, so
// editing anything else on an existing policy kept returning the config parsed
// the first time until the process restarted.
func TestConfigCacheSeesEditsToAnySetting(t *testing.T) {
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)

	withHeadChars := func(headChars int) map[string]any {
		return map[string]any{
			"collector_id": testCollectorID,
			"streaming": map[string]any{
				"enabled":    true,
				"head_chars": headChars,
			},
		}
	}

	first, err := p.config(withHeadChars(400))
	require.NoError(t, err)
	require.Equal(t, 400, first.Streaming.HeadChars)

	edited, err := p.config(withHeadChars(900))
	require.NoError(t, err)
	assert.Equal(t, 900, edited.Streaming.HeadChars,
		"editing a setting outside the old direction/collector_id/on_error tuple must take effect without a restart")

	back, err := p.config(withHeadChars(400))
	require.NoError(t, err)
	assert.Equal(t, 400, back.Streaming.HeadChars,
		"reverting the edit must resolve to the original config, not the last one parsed")

	entries := 0
	p.cfgCache.Range(func(any, any) bool {
		entries++
		return true
	})
	assert.Equal(t, 2, entries,
		"disabling the cache also satisfies the assertions above; this pins that one entry per distinct settings map is still cached")
}

func TestStreamingDefaults(t *testing.T) {
	cfg, err := parseConfig(map[string]any{"collector_id": testCollectorID, "on_error": onErrorFailClosed})
	require.NoError(t, err)

	assert.False(t, cfg.Streaming.Enabled)
	assert.Equal(t, defaultStreamingHeadChars, cfg.Streaming.HeadChars)
	assert.Equal(t, defaultStreamingMinCharsBetweenEvals, cfg.Streaming.MinCharsBetweenEvals)
	assert.Equal(t, defaultStreamingMaxHoldMS, cfg.Streaming.MaxHoldMS)
	assert.Equal(t, defaultStreamingMaxAccumulatedBytes, cfg.Streaming.MaxAccumulatedBytes)
	assert.True(t, cfg.Streaming.finalPass())
	assert.Equal(t, defaultStreamingGuardTimeout, cfg.Streaming.guardTimeout())
	assert.Equal(t, onErrorFailClosed, cfg.Streaming.OnError,
		"streaming.on_error inherits the policy on_error when unset")
	assert.True(t, cfg.Streaming.failClosedOnTransport())
}

func TestStreamingExplicitValues(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"on_error":     onErrorFailClosed,
		"streaming": map[string]any{
			"enabled":                 true,
			"head_chars":              1024,
			"min_chars_between_evals": 4096,
			"max_hold_ms":             1500,
			"max_accumulated_bytes":   524288,
			"final_pass":              false,
			"guard_timeout":           "3s",
			"on_error":                onErrorFailOpen,
		},
	})
	require.NoError(t, err)

	assert.True(t, cfg.Streaming.Enabled)
	assert.Equal(t, 1024, cfg.Streaming.HeadChars)
	assert.Equal(t, 4096, cfg.Streaming.MinCharsBetweenEvals)
	assert.Equal(t, 1500, cfg.Streaming.MaxHoldMS)
	assert.Equal(t, 524288, cfg.Streaming.MaxAccumulatedBytes)
	require.NotNil(t, cfg.Streaming.FinalPass)
	assert.False(t, *cfg.Streaming.FinalPass)
	assert.False(t, cfg.Streaming.finalPass(), "an explicit final_pass: false must not be taken for an absent key")
	assert.Equal(t, 3*time.Second, cfg.Streaming.guardTimeout())
	assert.Equal(t, onErrorFailOpen, cfg.Streaming.OnError,
		"an explicit streaming.on_error overrides the policy on_error")
	assert.False(t, cfg.Streaming.failClosedOnTransport())
}

func TestStreamingRanges(t *testing.T) {
	tests := []struct {
		name      string
		streaming map[string]any
		wantErr   bool
	}{
		{name: "head_chars at the floor", streaming: map[string]any{"head_chars": minStreamingHeadChars}},
		{name: "head_chars at the ceiling", streaming: map[string]any{"head_chars": maxStreamingHeadChars}},
		{name: "head_chars above the ceiling", streaming: map[string]any{"head_chars": maxStreamingHeadChars + 1}, wantErr: true},
		{name: "head_chars negative", streaming: map[string]any{"head_chars": -1}, wantErr: true},

		{name: "min_chars_between_evals at the floor", streaming: map[string]any{"min_chars_between_evals": minStreamingMinCharsBetweenEvals}},
		{name: "min_chars_between_evals at the ceiling", streaming: map[string]any{"min_chars_between_evals": maxStreamingMinCharsBetweenEvals}},
		{name: "min_chars_between_evals below the floor", streaming: map[string]any{"min_chars_between_evals": minStreamingMinCharsBetweenEvals - 1}, wantErr: true},
		{name: "min_chars_between_evals above the ceiling", streaming: map[string]any{"min_chars_between_evals": maxStreamingMinCharsBetweenEvals + 1}, wantErr: true},

		{name: "max_hold_ms at the floor", streaming: map[string]any{"max_hold_ms": minStreamingMaxHoldMS}},
		{name: "max_hold_ms at the ceiling", streaming: map[string]any{"max_hold_ms": maxStreamingMaxHoldMS}},
		{name: "max_hold_ms below the floor", streaming: map[string]any{"max_hold_ms": minStreamingMaxHoldMS - 1}, wantErr: true},
		{name: "max_hold_ms above the ceiling", streaming: map[string]any{"max_hold_ms": maxStreamingMaxHoldMS + 1}, wantErr: true},

		{name: "max_accumulated_bytes at the floor", streaming: map[string]any{"max_accumulated_bytes": minStreamingMaxAccumulatedBytes}},
		{name: "max_accumulated_bytes at the 1 MiB ceiling", streaming: map[string]any{"max_accumulated_bytes": maxStreamingMaxAccumulatedBytes}},
		{name: "max_accumulated_bytes below the floor", streaming: map[string]any{"max_accumulated_bytes": minStreamingMaxAccumulatedBytes - 1}, wantErr: true},
		{name: "max_accumulated_bytes above 1 MiB", streaming: map[string]any{"max_accumulated_bytes": maxStreamingMaxAccumulatedBytes + 1}, wantErr: true},

		{name: "guard_timeout at the floor", streaming: map[string]any{"guard_timeout": minStreamingGuardTimeout.String()}},
		{name: "guard_timeout at the ceiling", streaming: map[string]any{"guard_timeout": maxStreamingGuardTimeout.String()}},
		{name: "guard_timeout below the floor", streaming: map[string]any{"guard_timeout": "249ms"}, wantErr: true},
		{name: "guard_timeout above the ceiling", streaming: map[string]any{"guard_timeout": "10s1ms"}, wantErr: true},
		{name: "guard_timeout unparseable", streaming: map[string]any{"guard_timeout": "soon"}, wantErr: true},

		{name: "streaming on_error fail_closed", streaming: map[string]any{"on_error": onErrorFailClosed}},
		{name: "streaming on_error invalid", streaming: map[string]any{"on_error": "panic"}, wantErr: true},

		// pluginutil.Parse uses ErrorUnused: false, so a misspelled key is
		// accepted and simply does nothing.
		{name: "misspelled key is silently accepted", streaming: map[string]any{"head_charz": 99999}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(map[string]any{
				"collector_id": testCollectorID,
				"streaming":    tt.streaming,
			})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestStreamingMisspelledKeyKeepsTheDefault pins the consequence of
// ErrorUnused: false in pluginutil.Decode — a typo is not rejected, so the
// field it was meant to set silently keeps its default.
func TestStreamingMisspelledKeyKeepsTheDefault(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"streaming":    map[string]any{"head_charz": 99999},
	})
	require.NoError(t, err)
	assert.Equal(t, defaultStreamingHeadChars, cfg.Streaming.HeadChars)
}

func TestSelectsStage(t *testing.T) {
	tests := []struct {
		name             string
		direction        string
		wantPreRequest   bool
		wantPreResponse  bool
		wantPostResponse bool
	}{
		{name: "request", direction: legRequest, wantPreRequest: true, wantPreResponse: false, wantPostResponse: false},
		{name: "response", direction: legResponse, wantPreRequest: false, wantPreResponse: true, wantPostResponse: true},
		{name: "request_response", direction: legRequestResponse, wantPreRequest: true, wantPreResponse: true, wantPostResponse: true},
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
