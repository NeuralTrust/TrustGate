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

package configsnapshot

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func storedWithEveryRemovedKey(extra map[string]any) map[string]any {
	set := map[string]any{
		"on_error":        "fail_closed",
		"on_timeout":      "fail_closed",
		"timeout":         "1ms",
		"on_mask_failure": "block",
		"streaming": map[string]any{
			"enabled":       true,
			"head_chars":    64,
			"on_error":      "fail_closed",
			"guard_timeout": "1ms",
		},
	}
	for k, v := range extra {
		set[k] = v
	}
	return set
}

func TestWithoutRemovedSettings(t *testing.T) {
	t.Parallel()

	t.Run("trustguard loses every removed key and keeps the rest", func(t *testing.T) {
		t.Parallel()
		got := withoutRemovedSettings(policydomain.Policy{
			Slug:     "trustguard",
			Settings: storedWithEveryRemovedKey(map[string]any{"collector_id": "c-1", "direction": "request"}),
		})
		assert.Equal(t, map[string]any{
			"collector_id": "c-1",
			"direction":    "request",
			"streaming":    map[string]any{"enabled": true, "head_chars": 64},
		}, got.Settings)
	})

	t.Run("each guardrail loses its own keys", func(t *testing.T) {
		t.Parallel()
		for slug, want := range map[string]map[string]any{
			"bedrock_guardrail":    {"timeout": "1ms", "on_timeout": "fail_closed", "streaming": map[string]any{"enabled": true, "head_chars": 64}},
			"google_model_armor":   {"timeout": "1ms", "on_timeout": "fail_closed", "streaming": map[string]any{"enabled": true, "head_chars": 64}},
			"openai_moderation":    {"timeout": "1ms", "on_timeout": "fail_closed", "on_mask_failure": "block", "streaming": map[string]any{"enabled": true, "head_chars": 64}},
			"azure_content_safety": {"timeout": "1ms", "on_timeout": "fail_closed", "on_mask_failure": "block", "streaming": map[string]any{"enabled": true, "head_chars": 64, "on_error": "fail_closed", "guard_timeout": "1ms"}},
		} {
			got := withoutRemovedSettings(policydomain.Policy{Slug: slug, Settings: storedWithEveryRemovedKey(nil)})
			assert.Equal(t, want, got.Settings, slug)
		}
	})

	t.Run("regex_replace only loses on_mask_failure: its stream stays fail closed", func(t *testing.T) {
		t.Parallel()
		got := withoutRemovedSettings(policydomain.Policy{Slug: "regex_replace", Settings: storedWithEveryRemovedKey(nil)})
		want := storedWithEveryRemovedKey(nil)
		delete(want, "on_mask_failure")
		assert.Equal(t, want, got.Settings)
		assert.Equal(t, "fail_closed", got.Settings["streaming"].(map[string]any)["on_error"])
	})

	t.Run("a plugin with no removed setting is returned as it is", func(t *testing.T) {
		t.Parallel()
		set := map[string]any{"timeout": "5s", "on_error": "x"}
		got := withoutRemovedSettings(policydomain.Policy{Slug: "rate_limiter", Settings: set})
		assert.Equal(t, set, got.Settings, "timeout is a key of other plugins and is only removed from trustguard")
	})

	t.Run("the stored settings are never edited", func(t *testing.T) {
		t.Parallel()
		set := storedWithEveryRemovedKey(nil)
		_ = withoutRemovedSettings(policydomain.Policy{Slug: "trustguard", Settings: set})
		assert.Equal(t, storedWithEveryRemovedKey(nil), set)
	})

	t.Run("nil and settings without the keys are untouched", func(t *testing.T) {
		t.Parallel()
		got := withoutRemovedSettings(policydomain.Policy{Slug: "trustguard"})
		assert.Nil(t, got.Settings)
		clean := map[string]any{"collector_id": "c-1", "streaming": "not a map"}
		got = withoutRemovedSettings(policydomain.Policy{Slug: "trustguard", Settings: clean})
		require.Equal(t, clean, got.Settings)
	})
}
