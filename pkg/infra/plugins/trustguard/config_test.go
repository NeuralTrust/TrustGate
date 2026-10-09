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
	}{
		{
			name:          "valid minimal config defaults direction",
			settings:      map[string]any{"collector_id": testCollectorID},
			wantDirection: legRequestResponse,
		},
		{
			name:          "direction request accepted",
			settings:      map[string]any{"direction": legRequest, "collector_id": testCollectorID},
			wantDirection: legRequest,
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
		},
		{
			// Nothing reads the legacy key, so a policy that stores only it
			// falls back to the default. The accompanying migration is what
			// keeps that from changing behaviour on deploy.
			name:          "legacy inspect key alone falls back to the default",
			settings:      map[string]any{"inspect": legRequest, "collector_id": testCollectorID},
			wantDirection: legRequestResponse,
		},
		{
			name:          "direction response accepted",
			settings:      map[string]any{"direction": legResponse, "collector_id": testCollectorID},
			wantDirection: legResponse,
		},
		{
			name:          "direction request_response accepted",
			settings:      map[string]any{"direction": legRequestResponse, "collector_id": testCollectorID},
			wantDirection: legRequestResponse,
		},
		{
			name: "every removed failure key is accepted whatever its value",
			settings: map[string]any{
				"collector_id": testCollectorID, "on_error": "panic", "on_timeout": "fail_closed",
				"timeout": "1ms", "on_mask_failure": "block",
			},
			wantDirection: legRequestResponse,
		},
		{
			name:     "invalid direction",
			settings: map[string]any{"direction": "both", "collector_id": testCollectorID},
			wantErr:  true,
		},
		{
			name:          "legacy base_url in settings ignored",
			settings:      map[string]any{"base_url": "http://guard.local", "collector_id": testCollectorID},
			wantDirection: legRequestResponse,
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
	cfg, err := parseConfig(map[string]any{"collector_id": testCollectorID})
	require.NoError(t, err)

	assert.True(t, cfg.Streaming.IsEnabled(),
		"a policy that says nothing about streaming inspects streamed responses: RUN-1712")
	assert.Equal(t, defaultStreamingHeadChars, cfg.Streaming.HeadChars)
	assert.Equal(t, defaultStreamingMinCharsBetweenEvals, cfg.Streaming.MinCharsBetweenEvals)
	assert.Equal(t, defaultStreamingMaxHoldMS, cfg.Streaming.MaxHoldMS)
	assert.Equal(t, defaultStreamingMaxAccumulatedBytes, cfg.Streaming.MaxAccumulatedBytes)
}

func TestStreamingExplicitValues(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"collector_id": testCollectorID,
		"streaming": map[string]any{
			"enabled":                 true,
			"head_chars":              1024,
			"min_chars_between_evals": 4096,
			"max_hold_ms":             1500,
			"max_accumulated_bytes":   524288,
			"final_pass":              false,
			"guard_timeout":           "3s",
			"on_error":                "fail_closed",
		},
	})
	require.NoError(t, err)

	assert.True(t, cfg.Streaming.IsEnabled())
	assert.Equal(t, 1024, cfg.Streaming.HeadChars)
	assert.Equal(t, 4096, cfg.Streaming.MinCharsBetweenEvals)
	assert.Equal(t, 1500, cfg.Streaming.MaxHoldMS)
	assert.Equal(t, 524288, cfg.Streaming.MaxAccumulatedBytes)
}

func TestStreamingRanges(t *testing.T) {
	tests := []struct {
		name      string
		streaming map[string]any
		wantErr   bool
	}{
		{name: "head_chars at the floor", streaming: map[string]any{"head_chars": 1}},
		{name: "head_chars at the ceiling", streaming: map[string]any{"head_chars": 4096}},
		{name: "head_chars above the ceiling", streaming: map[string]any{"head_chars": 4096 + 1}, wantErr: true},
		{name: "head_chars negative", streaming: map[string]any{"head_chars": -1}, wantErr: true},

		{name: "min_chars_between_evals at the floor", streaming: map[string]any{"min_chars_between_evals": 256}},
		{name: "min_chars_between_evals at the ceiling", streaming: map[string]any{"min_chars_between_evals": 65536}},
		{name: "min_chars_between_evals below the floor", streaming: map[string]any{"min_chars_between_evals": 256 - 1}, wantErr: true},
		{name: "min_chars_between_evals above the ceiling", streaming: map[string]any{"min_chars_between_evals": 65536 + 1}, wantErr: true},

		{name: "max_hold_ms at the floor", streaming: map[string]any{"max_hold_ms": 50}},
		{name: "max_hold_ms at the ceiling", streaming: map[string]any{"max_hold_ms": 5000}},
		{name: "max_hold_ms below the floor", streaming: map[string]any{"max_hold_ms": 50 - 1}, wantErr: true},
		{name: "max_hold_ms above the ceiling", streaming: map[string]any{"max_hold_ms": 5000 + 1}, wantErr: true},

		{name: "max_accumulated_bytes at the floor", streaming: map[string]any{"max_accumulated_bytes": 4096}},
		{name: "max_accumulated_bytes at the 1 MiB ceiling", streaming: map[string]any{"max_accumulated_bytes": 1048576}},
		{name: "max_accumulated_bytes below the floor", streaming: map[string]any{"max_accumulated_bytes": 4096 - 1}, wantErr: true},
		{name: "max_accumulated_bytes above 1 MiB", streaming: map[string]any{"max_accumulated_bytes": 1048576 + 1}, wantErr: true},

		{name: "stored guard_timeout is ignored whatever its value", streaming: map[string]any{"guard_timeout": "soon"}},
		{name: "stored streaming on_error is ignored whatever its value", streaming: map[string]any{"on_error": "panic"}},

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

func TestValidateSettingsWriteRejectsFinalPassOptOut(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	settings := map[string]any{}
	settings["streaming"] = map[string]any{"final_pass": false}

	err := p.ValidateSettingsWrite(settings, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "streaming.final_pass")
	require.NoError(t, p.ValidateSettingsWrite(settings, settings),
		"a policy already stored with final_pass: false must stay editable")
}

// The per-block deadline is the short stream default, bounded above by the
// deployment-wide timeout. Neither a stored streaming.guard_timeout nor a looser
// deployment timeout moves it.
func TestStreamGuardTimeoutIsTheStreamDefaultCappedByTheDeploymentTimeout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		deployment time.Duration
		want       time.Duration
	}{
		{"default deployment timeout", 30 * time.Second, defaultStreamingGuardTimeout},
		{"deployment timeout tighter than the stream default", time.Second, time.Second},
		{"deployment timeout equal", defaultStreamingGuardTimeout, defaultStreamingGuardTimeout},
		{"unset deployment timeout", 0, defaultStreamingGuardTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Plugin{timeout: tc.deployment}
			assert.Equal(t, tc.want, p.streamGuardTimeout())
		})
	}
}
