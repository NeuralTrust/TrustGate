//go:build functional

package functional_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Templates the Model Armor stub answers apart: one never answers within a
// second, one answers 503 at once.
const (
	modelArmorSlowTemplate = "slow-template"
	modelArmorDownTemplate = "down-template"
	modelArmorSlowDelay    = 2500 * time.Millisecond
)

func modelArmorFailurePolicy(template string, stage string, extra map[string]any) map[string]any {
	settings := modelArmorSettings("block")
	settings["template"] = template
	for k, v := range extra {
		settings[k] = v
	}
	entry := policyPlugin("google_model_armor", settings)
	entry["stages"] = []string{stage}
	return entry
}

// A policy decides "can't be reached" (failure_mode) and "too slow"
// (timeout_failure_mode) apart, against a running gateway.
func TestPluginE2E_GoogleModelArmor_TimeoutAndOutageModes(t *testing.T) {
	defer Track(t, "PluginGoogleModelArmor")()

	newModelArmorStub(t)

	limit := map[string]any{"timeout_seconds": 1}
	with := func(kv map[string]any) map[string]any {
		out := map[string]any{"timeout_seconds": 1}
		for k, v := range kv {
			out[k] = v
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		template string
		mode     string
		settings map[string]any
		blocked  bool
	}{
		{"legacy open lets a slow answer through", modelArmorSlowTemplate, "enforce", limit, false},
		{"legacy closed blocks a slow answer", modelArmorSlowTemplate, "enforce", with(map[string]any{"failure_mode": "closed"}), true},
		{"block outages, allow slow: outage blocked", modelArmorDownTemplate, "enforce", with(map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}), true},
		{"block outages, allow slow: slow let through", modelArmorSlowTemplate, "enforce", with(map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}), false},
		{"allow outages, block slow: outage let through", modelArmorDownTemplate, "enforce", with(map[string]any{"timeout_failure_mode": "closed"}), false},
		{"allow outages, block slow: slow blocked", modelArmorSlowTemplate, "enforce", with(map[string]any{"timeout_failure_mode": "closed"}), true},
		{"observe never blocks a closed timeout", modelArmorSlowTemplate, "observe", with(map[string]any{"failure_mode": "closed", "timeout_failure_mode": "closed"}), false},
		{"observe never blocks a closed outage", modelArmorDownTemplate, "observe", with(map[string]any{"failure_mode": "closed", "timeout_failure_mode": "closed"}), false},
		{"empty limit uses the 15 s default", modelArmorSlowTemplate, "enforce", map[string]any{"timeout_failure_mode": "closed"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newJSONUpstream(t, "model-armor-failure-mode")
			entry := modelArmorFailurePolicy(tc.template, "pre_request", tc.settings)
			entry["mode"] = tc.mode
			apiKey, path := setupPolicyRoute(t, up, entry)

			status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
				mustJSON(t, modelArmorChatRequest("hello there, how are you today?")))
			if tc.blocked {
				assert.Equal(t, http.StatusForbidden, status, "body: %s", raw)
				assert.Contains(t, string(raw), "guardrail_input_uninspectable")
				assert.Zero(t, up.Hits(), "a refused request must not reach the upstream")
				return
			}
			assert.Equal(t, http.StatusOK, status, "body: %s", raw)
			assert.Contains(t, string(raw), "model-armor-failure-mode")
		})
	}
}

// A streamed block that Model Armor does not answer within its 2 s limit
// follows timeout_failure_mode, whatever failure_mode says.
func TestPluginE2E_GoogleModelArmor_SlowStreamedBlockFollowsTheTimeoutMode(t *testing.T) {
	defer Track(t, "PluginGoogleModelArmor")()

	newModelArmorStub(t)

	for _, tc := range []struct {
		name     string
		settings map[string]any
		released bool
	}{
		{"block outages, allow slow: released", map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}, true},
		{"allow outages, block slow: withheld", map[string]any{"timeout_failure_mode": "closed"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newStreamUpstream(t, "model-armor-streamed")
			apiKey, path := setupPolicyRoute(t, up, modelArmorFailurePolicy(modelArmorSlowTemplate, "pre_response", tc.settings))

			req := modelArmorChatRequest("hello there, how are you today?")
			req["stream"] = true
			status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil, mustJSON(t, req))
			require.NotZero(t, status)
			if tc.released {
				assert.Equal(t, http.StatusOK, status, "body: %s", raw)
				assert.Contains(t, string(raw), "model-armor-streamed")
				return
			}
			assert.NotContains(t, string(raw), "model-armor-streamed", "status %d", status)
		})
	}
}
