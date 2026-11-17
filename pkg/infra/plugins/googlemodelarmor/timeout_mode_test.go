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

package googlemodelarmor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func settingsWith(kv map[string]any) map[string]any {
	set := validSettings()
	for k, v := range kv {
		set[k] = v
	}
	return set
}

func TestParseConfigTimeoutSettings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		settings    map[string]any
		wantErr     string
		timeoutMode string
		seconds     int
	}{
		{name: "empty follows the open default", settings: nil, timeoutMode: "open"},
		{name: "empty follows failure_mode closed", settings: map[string]any{"failure_mode": "closed"}, timeoutMode: "closed"},
		{name: "explicit open under closed", settings: map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}, timeoutMode: "open"},
		{name: "explicit closed under open", settings: map[string]any{"timeout_failure_mode": "closed"}, timeoutMode: "closed"},
		{name: "unknown timeout mode", settings: map[string]any{"timeout_failure_mode": "maybe"}, wantErr: "timeout_failure_mode must be one of open, closed"},
		{name: "seconds from a JSON number", settings: map[string]any{"timeout_seconds": float64(5)}, timeoutMode: "open", seconds: 5},
		{name: "seconds at the maximum", settings: map[string]any{"timeout_seconds": 60}, timeoutMode: "open", seconds: 60},
		{name: "zero seconds is the gateway default", settings: map[string]any{"timeout_seconds": 0}, timeoutMode: "open"},
		{name: "seconds above the maximum", settings: map[string]any{"timeout_seconds": 61}, wantErr: "timeout_seconds must be between 1 and 60"},
		{name: "negative seconds", settings: map[string]any{"timeout_seconds": -1}, wantErr: "timeout_seconds must be between 1 and 60"},
		{name: "seconds not a number", settings: map[string]any{"timeout_seconds": "soon"}, wantErr: "timeout_seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(settingsWith(tc.settings))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.timeoutMode, cfg.TimeoutFailureMode)
			assert.Equal(t, tc.seconds, cfg.TimeoutSeconds)
		})
	}
}

func TestCallTimeout(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 15*time.Second, Settings{}.callTimeout(15*time.Second))
	assert.Equal(t, 3*time.Second, Settings{TimeoutSeconds: 3}.callTimeout(15*time.Second))
	assert.Equal(t, 40*time.Second, Settings{TimeoutSeconds: 40}.callTimeout(15*time.Second))
}

func TestFailClosedForSplitsTimeoutFromOtherFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		settings      map[string]any
		closed        bool
		timeoutClosed bool
	}{
		{"legacy open", nil, false, false},
		{"legacy closed covers timeouts", map[string]any{"failure_mode": "closed"}, true, true},
		{"block outages, allow slow", map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}, true, false},
		{"allow outages, block slow", map[string]any{"failure_mode": "open", "timeout_failure_mode": "closed"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := settingsWith(tc.settings)
			cfg, err := parseConfig(set)
			require.NoError(t, err)
			assert.Equal(t, tc.closed, cfg.failClosedFor(""))
			assert.Equal(t, tc.closed, cfg.failClosedFor(appplugins.DetailThrottled))
			assert.Equal(t, tc.timeoutClosed, cfg.failClosedFor(appplugins.DetailTimeout))
			assert.Equal(t, tc.closed || tc.timeoutClosed, cfg.mayFailClosed())
			assert.Equal(t, tc.closed, failClosedOf(set, ""))
			assert.Equal(t, tc.timeoutClosed, failClosedOf(set, appplugins.DetailTimeout))
			assert.Equal(t, appplugins.Blocks(policy.ModeEnforce) && !tc.timeoutClosed,
				cfg.keepsMaskOnGap(policy.ModeEnforce, appplugins.DetailTimeout))
		})
	}
}

// Settings that do not parse still decide each failure from the mode the
// policy asked for, read leniently.
func TestFailClosedOfUnparseableSettingsReadsBothModes(t *testing.T) {
	t.Parallel()
	broken := map[string]any{"failure_mode": "closed", "timeout_failure_mode": " Open "}
	assert.True(t, failClosedOf(broken, ""))
	assert.False(t, failClosedOf(broken, appplugins.DetailTimeout))
	assert.True(t, mayFailClosedOf(broken))

	onlyTimeout := map[string]any{"Timeout_Failure_Mode": "CLOSED"}
	assert.False(t, failClosedOf(onlyTimeout, ""))
	assert.True(t, failClosedOf(onlyTimeout, appplugins.DetailTimeout))
	assert.True(t, mayFailClosedOf(onlyTimeout))

	legacy := map[string]any{"failure_mode": "closed"}
	assert.True(t, failClosedOf(legacy, appplugins.DetailTimeout), "an absent timeout mode follows failure_mode")

	assert.False(t, mayFailClosedOf(map[string]any{"timeout_failure_mode": 1}))
}
