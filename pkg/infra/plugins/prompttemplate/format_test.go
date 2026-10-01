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

package prompttemplate

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func injectSettings(role, onExisting, content string) map[string]any {
	return map[string]any{
		"inject_templates": []any{
			map[string]any{
				"id": "a", "position": "system", "role": role,
				"content": content, "on_existing_system": onExisting,
			},
		},
	}
}

// runPlugin executes the plugin and returns the forwarded body (the original
// when the plugin did not rewrite it) and the event it recorded.
func runPlugin(t *testing.T, mode policy.Mode, settings map[string]any, provider, sourceFormat, body string) (string, PromptTemplateData) {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    mode,
		Config:  policy.PluginConfig{Settings: settings},
		Request: &infracontext.RequestContext{Provider: provider, SourceFormat: sourceFormat, Body: []byte(body)},
		Event:   metrics.NewEventContext(span),
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	data, ok := span.PluginAttrsCopy().Extras.(PromptTemplateData)
	require.True(t, ok, "extras must be PromptTemplateData")
	if res.RequestBody == nil {
		return body, data
	}
	return string(res.RequestBody), data
}

func TestExecuteUnsupportedFormatPassesThrough(t *testing.T) {
	body := `{"model":"m","input":"hi","messages":[{"role":"user","content":"{template://x}"}]}`
	tests := []struct {
		name         string
		provider     string
		sourceFormat string
		wantReason   string
	}{
		{"openai responses", "openai", "openai_responses", "unsupported_format:openai_responses"},
		{"bedrock", "bedrock", "", "unsupported_format:bedrock"},
		{"embeddings", "openai", "openai_embeddings", "unsupported_format:openai_embeddings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := geminiModeBSettings()
			settings["allow_untemplated_requests"] = true
			got, data := runPlugin(t, policy.ModeEnforce, settings, tt.provider, tt.sourceFormat, body)
			assert.Equal(t, body, got, "an unsupported format must reach the upstream untouched")
			assert.Equal(t, decisionSkippedFormat, data.Decision)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
			assert.Empty(t, data.InjectedIDs)
			assert.True(t, data.UnscannedTemplateReference)
		})
	}

	t.Run("no reference is not flagged", func(t *testing.T) {
		plain := `{"input":"hi"}`
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), "openai", "openai_responses", plain)
		assert.Equal(t, plain, got)
		assert.False(t, data.UnscannedTemplateReference)
	})

	t.Run("properties are still stripped", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), "openai", "openai_responses", `{"input":"hi","properties":{"a":"b"}}`)
		assert.JSONEq(t, `{"input":"hi"}`, got)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
	})

	t.Run("observe records the decision too", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeObserve, injectSettings("system", "merge", "be brief"), "openai", "openai_responses", body)
		assert.Equal(t, body, got)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
	})
}

func TestExecuteShapeVetoesPassThrough(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		body       string
		wantReason string
	}{
		{"messages not an array", "openai", `{"messages":"opaque"}`, "messages_not_array"},
		{"gemini with both spellings", "google", `{"contents":[],"systemInstruction":{"parts":[{"text":"a"}]},"system_instruction":{"parts":[{"text":"b"}]}}`, "ambiguous_gemini_keys"},
		{"gemini contents not an array", "google", `{"contents":"opaque"}`, "contents_not_array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), tt.provider, "", tt.body)
			assert.Equal(t, tt.body, got)
			assert.Equal(t, decisionSkippedShape, data.Decision)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
		})
	}
}

func TestExecuteSupportedFormatsStillInject(t *testing.T) {
	for _, provider := range []string{"openai", "azure", "groq", "deepseek", "xai", "openrouter", "cohere", "mistral"} {
		t.Run(provider, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), provider, "", `{"messages":[{"role":"user","content":"hi"}]}`)
			assert.JSONEq(t, `{"messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}]}`, got)
			assert.Equal(t, decisionInjected, data.Decision)
			assert.Equal(t, []string{"a"}, data.InjectedIDs)
		})
	}
}

func geminiOut(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal([]byte(raw), &out))
	return out
}

func TestGeminiModeASystem(t *testing.T) {
	tests := []struct {
		name       string
		onExisting string
		body       string
		want       string
	}{
		{
			name: "absent creates systemInstruction", onExisting: "merge",
			body: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
			want: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"parts":[{"text":"INJ"}]}}`,
		},
		{
			name: "merge appends a part and keeps non-text parts and role", onExisting: "merge",
			body: `{"systemInstruction":{"role":"system","parts":[{"text":"old"},{"inlineData":{"mimeType":"image/png","data":"AA=="}}]},"contents":[]}`,
			want: `{"systemInstruction":{"role":"system","parts":[{"text":"old"},{"inlineData":{"mimeType":"image/png","data":"AA=="}},{"text":"INJ"}]},"contents":[]}`,
		},
		{
			name: "replace leaves exactly one text part", onExisting: "replace",
			body: `{"systemInstruction":{"parts":[{"text":"old"},{"text":"older"}]},"contents":[]}`,
			want: `{"systemInstruction":{"parts":[{"text":"INJ"}]},"contents":[]}`,
		},
		{
			name: "snake_case spelling is written back as snake_case", onExisting: "merge",
			body: `{"system_instruction":{"parts":[{"text":"old"}]},"contents":[]}`,
			want: `{"system_instruction":{"parts":[{"text":"old"},{"text":"INJ"}]},"contents":[]}`,
		},
		{
			name: "snake_case replace", onExisting: "replace",
			body: `{"system_instruction":{"parts":[{"text":"old"}]},"contents":[]}`,
			want: `{"system_instruction":{"parts":[{"text":"INJ"}]},"contents":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", tt.onExisting, "INJ"), "google", "", tt.body)
			assert.JSONEq(t, tt.want, got)
			assert.Equal(t, decisionInjected, data.Decision)
			assert.Equal(t, []string{"a"}, data.InjectedIDs)
			assert.Empty(t, data.Unapplied)
			_, hasMessages := geminiOut(t, got)["messages"]
			assert.False(t, hasMessages, "a Gemini body must never grow a messages array")
		})
	}
}

func TestGeminiModeARoles(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`

	t.Run("user prepends a user turn", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "google", "", body)
		assert.JSONEq(t, `{"contents":[{"role":"user","parts":[{"text":"INJ"}]},{"role":"user","parts":[{"text":"hi"}]}]}`, got)
		assert.Equal(t, []string{"a"}, data.InjectedIDs)
	})
	for _, role := range []string{"assistant", "developer", "tool"} {
		t.Run(role+" is not applied and says why", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings(role, "merge", "INJ"), "google", "", body)
			assert.Equal(t, body, got)
			assert.Empty(t, data.InjectedIDs)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonRoleUnsupportedGemini}}, data.Unapplied)
			assert.NotEqual(t, decisionInjected, data.Decision)
		})
	}
}

func geminiModeBSettings() map[string]any {
	return map[string]any{
		"named_templates": []any{
			map[string]any{
				"name": "bot",
				"versions": []any{
					map[string]any{
						"labels":  []any{"stable"},
						"content": `[{"role":"system","content":"You are a bot."},{"role":"assistant","content":"Hello"},{"role":"user","content":[{"type":"text","text":"Go"}]}]`,
					},
				},
			},
		},
		"default_label": "stable",
	}
}

func TestGeminiModeB(t *testing.T) {
	t.Run("reference in contents is rendered and mapped", func(t *testing.T) {
		body := `{"systemInstruction":{"parts":[{"text":"keep"}]},"contents":[` +
			`{"role":"user","parts":[{"text":"earlier"}]},` +
			`{"role":"model","parts":[{"text":"answer"}]},` +
			`{"role":"user","parts":[{"text":"{template://bot@stable}"}]}]}`
		got, data := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "google", "", body)
		assert.JSONEq(t, `{"systemInstruction":{"parts":[{"text":"keep"},{"text":"You are a bot."}]},"contents":[`+
			`{"role":"model","parts":[{"text":"Hello"}]},{"role":"user","parts":[{"text":"Go"}]}]}`, got)
		assert.Equal(t, decisionRendered, data.Decision)
		assert.Equal(t, "bot", data.ResolvedTemplate)
		assert.Equal(t, 1, data.DiscardedMessages, "same net-turns-lost count as the messages path")
		assert.NotContains(t, got, "template://")
	})

	t.Run("plain string fragment becomes one user turn", func(t *testing.T) {
		settings := map[string]any{
			"named_templates": []any{map[string]any{
				"name": "p",
				"versions": []any{map[string]any{
					"labels": []any{"stable"}, "content": "Plain prompt",
				}},
			}},
			"default_label": "stable",
		}
		got, _ := runPlugin(t, policy.ModeEnforce, settings, "google", "", `{"contents":[{"role":"user","parts":[{"text":"{template://p}"}]}]}`)
		assert.JSONEq(t, `{"contents":[{"role":"user","parts":[{"text":"Plain prompt"}]}]}`, got)
	})

	t.Run("thought parts are not scanned", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"contents":[{"role":"model","parts":[{"text":"{template://leak}","thought":true},{"inlineData":{"data":"AA=="}},{"text":"{template://real@v1}"}]}]}`))
		require.NoError(t, err)
		rb.shape = shapeGemini
		assert.Equal(t, []templateRef{{name: "real", label: "v1"}}, rb.findReferences())
	})

	t.Run("two different references are ambiguous", func(t *testing.T) {
		_, err := New().Execute(context.Background(), appplugins.ExecInput{
			Mode:   policy.ModeEnforce,
			Config: policy.PluginConfig{Settings: geminiModeBSettings()},
			Request: &infracontext.RequestContext{Provider: "google", Body: []byte(
				`{"contents":[{"role":"user","parts":[{"text":"{template://bot@stable}"},{"text":"{template://other}"}]}]}`)},
		})
		pe := requirePluginError(t, err)
		assert.Equal(t, typeAmbiguous, pe.Type)
	})
}

func TestAnthropicSystemBlocks(t *testing.T) {
	body := `{"model":"c","system":[{"type":"text","text":"old","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`

	t.Run("merge appends a block and keeps cache_control", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "anthropic", "", body)
		assert.JSONEq(t, `{"model":"c","system":[{"type":"text","text":"old","cache_control":{"type":"ephemeral"}},{"type":"text","text":"INJ"}],"messages":[{"role":"user","content":"hi"}]}`, got)
		assert.Equal(t, []string{"a"}, data.InjectedIDs)
	})
	t.Run("replace sets a plain string", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "replace", "INJ"), "anthropic", "", body)
		assert.JSONEq(t, `{"model":"c","system":"INJ","messages":[{"role":"user","content":"hi"}]}`, got)
	})
	t.Run("string system is unchanged behaviour", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "anthropic", "", `{"system":"old","messages":[]}`)
		assert.JSONEq(t, `{"system":"old\n\nINJ","messages":[]}`, got)
	})
}

func TestModeAEventIsHonest(t *testing.T) {
	t.Run("unapplied injection is not reported as injected", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
			{ID: "bad", Position: "system", Role: roleSystem, Content: "x", OnExistingSystem: onExistingMerge},
			{ID: "ok", Position: "system", Role: roleSystem, Content: "y", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"systemInstruction":"not-an-object","contents":[]}`))
		require.NoError(t, err)
		rb.shape = shapeGemini
		outcome := applyModeA(cfg, rb, nil)
		assert.False(t, outcome.changed)
		assert.Empty(t, outcome.injected)
		assert.Equal(t, []unappliedInjection{
			{ID: "bad", Reason: reasonSystemInstructionBad},
			{ID: "ok", Reason: reasonSystemInstructionBad},
		}, outcome.unapplied)
		assert.NotEqual(t, decisionInjected, enforceData(outcome, modeBResult{}).Decision)
		assert.False(t, rb.dirty())
	})

	t.Run("opaque messages with a non-system role is unapplied", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":"opaque"}`))
		require.NoError(t, err)
		applied, reason := rb.injectSystem(onExistingMerge, roleSystem, "x")
		assert.False(t, applied)
		assert.Equal(t, reasonMessagesNotArray, reason)
	})

	t.Run("mixed outcome reports only the applied id", func(t *testing.T) {
		settings := map[string]any{"inject_templates": []any{
			map[string]any{"id": "sys", "position": "system", "role": "system", "content": "S", "on_existing_system": "merge"},
			map[string]any{"id": "dev", "position": "system", "role": "developer", "content": "D", "on_existing_system": "merge"},
		}}
		_, data := runPlugin(t, policy.ModeEnforce, settings, "google", "", `{"contents":[]}`)
		assert.Equal(t, decisionInjected, data.Decision)
		assert.Equal(t, []string{"sys"}, data.InjectedIDs)
		assert.Equal(t, []unappliedInjection{{ID: "dev", Reason: reasonRoleUnsupportedGemini}}, data.Unapplied)
	})
}

// The gateway decodes the plugin's output with the real adapter before it
// reaches the model, so the injected text has to survive that decode. Unit
// tests on the raw JSON alone passed for the bug this guards: the plugin wrote
// a messages array that Gemini's decoder never reads.
func TestGeminiOutputSurvivesRealAdapterDecode(t *testing.T) {
	registry := adapter.NewRegistry()
	body := `{"model":"gemini-2.5-pro","contents":[{"role":"user","parts":[{"text":"hi"}]}]}`

	got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJECTED-SYSTEM"), "google", "", body)
	require.Equal(t, decisionInjected, data.Decision)

	creq, err := registry.DecodeRequestFor([]byte(got), adapter.FormatGemini)
	require.NoError(t, err)
	assert.Contains(t, creq.System, "INJECTED-SYSTEM")

	encoded, err := registry.AdaptRequest([]byte(got), adapter.FormatGemini, adapter.FormatOpenAI)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(encoded), "INJECTED-SYSTEM"), "the injected text must reach an OpenAI upstream: %s", encoded)

	t.Run("merge keeps the client's own instruction too", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJECTED-SYSTEM"), "google", "",
			`{"systemInstruction":{"parts":[{"text":"CLIENT-SYSTEM"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`)
		creq, err := registry.DecodeRequestFor([]byte(got), adapter.FormatGemini)
		require.NoError(t, err)
		assert.Contains(t, creq.System, "CLIENT-SYSTEM")
		assert.Contains(t, creq.System, "INJECTED-SYSTEM")
	})
}

func TestExecuteSourceFormatDrivesTheShape(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	want := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"parts":[{"text":"INJ"}]}}`

	t.Run("source format google with an empty provider (the proxy path)", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "", "google", body)
		assert.JSONEq(t, want, got)
		assert.Equal(t, decisionInjected, data.Decision)
	})
	t.Run("source format wins over provider", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "google", body)
		assert.JSONEq(t, want, got)
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "google", "openai_responses", body)
		assert.Equal(t, body, got)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
	})
	t.Run("vertex is the Gemini shape", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "vertex", "", body)
		assert.JSONEq(t, want, got)
		assert.Equal(t, decisionInjected, data.Decision)
	})
	t.Run("an MCP call with no format is skipped, not guessed", func(t *testing.T) {
		rt := trace.New("t", trace.Metadata{})
		span := rt.StartSpan(trace.SpanPlugin, PluginName)
		res, err := New().Execute(context.Background(), appplugins.ExecInput{
			Mode:    policy.ModeEnforce,
			Config:  policy.PluginConfig{Settings: injectSettings("system", "merge", "INJ")},
			Request: &infracontext.RequestContext{MCP: true, Body: []byte(`{"name":"t","arguments":{}}`)},
			Event:   metrics.NewEventContext(span),
		})
		require.NoError(t, err)
		assert.Nil(t, res.RequestBody)
		data := span.PluginAttrsCopy().Extras.(PromptTemplateData)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
		assert.Equal(t, "unresolved_format", data.SkippedReason)
	})
}

func TestGeminiNonCanonicalKeysAreVetoed(t *testing.T) {
	for _, body := range []string{
		`{"Contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
		`{"contents":[],"SystemInstruction":{"parts":[{"text":"a"}]}}`,
		`{"contents":[],"SYSTEM_INSTRUCTION":{"parts":[{"text":"a"}]}}`,
		`{"contents":[],"system_Instruction":{"parts":[{"text":"a"}]}}`,
	} {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "google", "", body)
		assert.Equal(t, body, got)
		assert.Equal(t, decisionSkippedShape, data.Decision, body)
		assert.Equal(t, "non_canonical_gemini_key", data.SkippedReason, body)
	}
}

func TestAnthropicWithoutUsableSystem(t *testing.T) {
	for name, body := range map[string]string{
		"absent": `{"messages":[{"role":"user","content":"hi"}]}`,
		"null":   `{"system":null,"messages":[{"role":"user","content":"hi"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "anthropic", "", body)
			assert.JSONEq(t, `{"system":"INJ","messages":[{"role":"user","content":"hi"}]}`, got)
			assert.Equal(t, []string{"a"}, data.InjectedIDs)
		})
	}
	for name, system := range map[string]string{"object": `{"unexpected":true}`, "number": `7`, "bool": `true`} {
		t.Run(name+" system is not overwritten", func(t *testing.T) {
			body := `{"system":` + system + `,"messages":[{"role":"user","content":"hi"}]}`
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "anthropic", "", body)
			assert.JSONEq(t, body, got)
			assert.Empty(t, data.InjectedIDs)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonSystemUnreadable}}, data.Unapplied)
		})
	}
	t.Run("user and assistant prepend a turn", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("assistant", "merge", "INJ"), "anthropic", "", `{"messages":[{"role":"user","content":"hi"}]}`)
		assert.JSONEq(t, `{"messages":[{"role":"assistant","content":"INJ"},{"role":"user","content":"hi"}]}`, got)
	})
	for _, role := range []string{"developer", "tool"} {
		t.Run(role+" is unapplied", func(t *testing.T) {
			body := `{"messages":[{"role":"user","content":"hi"}]}`
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings(role, "merge", "INJ"), "anthropic", "", body)
			assert.Equal(t, body, got)
			assert.Empty(t, data.InjectedIDs)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonRoleUnsupportedAnthropic}}, data.Unapplied)
		})
	}
}

func TestUnscannedReferenceOnSupportedFormats(t *testing.T) {
	for name, tc := range map[string]struct{ provider, body string }{
		"openai content array":    {"openai", `{"messages":[{"role":"user","content":[{"type":"text","text":"{template://bot@stable}"}]}]}`},
		"anthropic content array": {"anthropic", `{"messages":[{"role":"user","content":[{"type":"text","text":"{template://bot@stable}"}]}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			settings := geminiModeBSettings()
			settings["allow_untemplated_requests"] = true
			got, data := runPlugin(t, policy.ModeEnforce, settings, tc.provider, "", tc.body)
			assert.Equal(t, tc.body, got, "content arrays are still not resolved")
			assert.True(t, data.UnscannedTemplateReference)
			assert.Empty(t, data.ResolvedTemplate)
		})
	}
	t.Run("a resolved reference is not flagged", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "openai", "", `{"messages":[{"role":"user","content":"{template://bot@stable}"}]}`)
		assert.False(t, data.UnscannedTemplateReference)
	})
	t.Run("no mode B configured is not flagged", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "x"), "openai", "", `{"messages":[{"role":"user","content":[{"type":"text","text":"{template://a}"}]}]}`)
		assert.False(t, data.UnscannedTemplateReference)
	})
}

func execGemini(t *testing.T, settings map[string]any, body string) error {
	t.Helper()
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: &infracontext.RequestContext{Provider: "google", Body: []byte(body)},
	})
	return err
}

func TestGeminiModeBFailures(t *testing.T) {
	ref := func(r string) string {
		return `{"contents":[{"role":"user","parts":[{"text":"` + r + `"}]}]}`
	}
	t.Run("unknown template", func(t *testing.T) {
		pe := requirePluginError(t, execGemini(t, geminiModeBSettings(), ref("{template://nope}")))
		assert.Equal(t, typeNotFound, pe.Type)
	})
	t.Run("unresolvable label", func(t *testing.T) {
		pe := requirePluginError(t, execGemini(t, geminiModeBSettings(), ref("{template://bot@v9}")))
		assert.Equal(t, typeNotFound, pe.Type)
	})
	t.Run("fragment with a non-text part", func(t *testing.T) {
		settings := map[string]any{
			"named_templates": []any{map[string]any{
				"name": "img",
				"versions": []any{map[string]any{
					"labels":  []any{"stable"},
					"content": `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://x"}}]}]`,
				}},
			}},
			"default_label": "stable",
		}
		pe := requirePluginError(t, execGemini(t, settings, ref("{template://img}")))
		assert.Equal(t, typeRenderFailed, pe.Type)
	})
}

func TestGeminiModeBFragmentEdges(t *testing.T) {
	settings := map[string]any{
		"named_templates": []any{map[string]any{
			"name": "edge",
			"versions": []any{map[string]any{
				"labels":  []any{"stable"},
				"content": `[{"role":"system","content":""},{"role":"assistant","content":null},{"role":"user","content":"Go"}]`,
			}},
		}},
		"default_label": "stable",
	}
	got, _ := runPlugin(t, policy.ModeEnforce, settings, "google", "", `{"systemInstruction":{"parts":[{"text":"keep"}]},"contents":[{"role":"user","parts":[{"text":"{template://edge}"}]}]}`)
	assert.JSONEq(t, `{"systemInstruction":{"parts":[{"text":"keep"}]},"contents":[{"role":"user","parts":[{"text":"Go"}]}]}`, got,
		"an empty system text adds no part and a null-content turn adds no empty turn")
}

func TestGeminiObserveLeavesBodyIdentical(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`
	got, data := runPlugin(t, policy.ModeObserve, injectSettings("system", "merge", "INJ"), "google", "", body)
	assert.Equal(t, body, got)
	assert.Equal(t, decisionObserved, data.Decision)
	assert.Equal(t, []string{"a"}, data.InjectedIDs, "observe reports what enforce would have done")
}

func TestGeminiModeBWithModeAReplace(t *testing.T) {
	settings := geminiModeBSettings()
	settings["inject_templates"] = []any{map[string]any{
		"id": "a", "position": "system", "role": "system", "content": "MODE-A", "on_existing_system": "replace",
	}}
	got, data := runPlugin(t, policy.ModeEnforce, settings, "google", "",
		`{"systemInstruction":{"parts":[{"text":"client"}]},"contents":[{"role":"user","parts":[{"text":"{template://bot@stable}"}]}]}`)
	assert.JSONEq(t, `{"systemInstruction":{"parts":[{"text":"MODE-A"}]},"contents":[`+
		`{"role":"model","parts":[{"text":"Hello"}]},{"role":"user","parts":[{"text":"Go"}]}]}`, got,
		"Mode B folds its system text in first, then Mode A replaces the whole instruction")
	assert.Equal(t, decisionInjected, data.Decision)
	assert.Equal(t, "bot", data.ResolvedTemplate)
}

func requiredModeBSettings() map[string]any {
	s := geminiModeBSettings()
	s["allow_untemplated_requests"] = false
	return s
}

func TestSkippedRequestsUnderRequiredModeB(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		sourceFormat string
		mcp          bool
		body         string
		wantReason   string
		wantDecision string
	}{
		{"openai responses", "openai", "openai_responses", false, `{"input":"hi"}`, "unsupported_format:openai_responses", decisionSkippedFormat},
		{"bedrock", "bedrock", "", false, `{"messages":[]}`, "unsupported_format:bedrock", decisionSkippedFormat},
		{"shape veto messages_not_array", "openai", "", false, `{"messages":"opaque"}`, "messages_not_array", decisionSkippedShape},
		{"responses-shaped body under a chat format", "openai", "", false, `{"input":"hi"}`, "responses_shaped_body", decisionSkippedShape},
		{"mcp unresolved format", "", "", true, `{"name":"t","arguments":{}}`, "unresolved_format", decisionSkippedFormat},
	}
	for _, tt := range tests {
		run := func(mode policy.Mode, settings map[string]any) (*appplugins.Result, PromptTemplateData, error) {
			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			res, err := New().Execute(context.Background(), appplugins.ExecInput{
				Mode:   mode,
				Config: policy.PluginConfig{Settings: settings},
				Request: &infracontext.RequestContext{
					Provider: tt.provider, SourceFormat: tt.sourceFormat, MCP: tt.mcp, Body: []byte(tt.body),
				},
				Event: metrics.NewEventContext(span),
			})
			data, _ := span.PluginAttrsCopy().Extras.(PromptTemplateData)
			return res, data, err
		}

		t.Run(tt.name+" enforce rejects with template_required", func(t *testing.T) {
			_, data, err := run(policy.ModeEnforce, requiredModeBSettings())
			pe := requirePluginError(t, err)
			assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
			assert.Equal(t, typeRequired, pe.Type)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
			assert.Equal(t, decisionNoOp, data.Decision)
		})
		t.Run(tt.name+" observe never blocks", func(t *testing.T) {
			res, data, err := run(policy.ModeObserve, requiredModeBSettings())
			require.NoError(t, err)
			assert.Nil(t, res.RequestBody)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
			assert.Equal(t, tt.wantDecision, data.Decision)
		})
		t.Run(tt.name+" permissive mode B passes through", func(t *testing.T) {
			settings := geminiModeBSettings()
			settings["allow_untemplated_requests"] = true
			res, data, err := run(policy.ModeEnforce, settings)
			require.NoError(t, err)
			assert.Nil(t, res.RequestBody)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
		})
		t.Run(tt.name+" mode A only passes through", func(t *testing.T) {
			res, data, err := run(policy.ModeEnforce, injectSettings("system", "merge", "x"))
			require.NoError(t, err)
			assert.Nil(t, res.RequestBody)
			assert.Equal(t, tt.wantReason, data.SkippedReason)
		})
	}
}

func TestResponsesShapedBodyUnderChatFormat(t *testing.T) {
	body := `{"input":"hi"}`
	for _, provider := range []string{"openai", "azure", "cohere", "mistral"} {
		t.Run(provider+" mode A passes through untouched", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), provider, "", body)
			assert.Equal(t, body, got)
			assert.Equal(t, decisionSkippedShape, data.Decision)
			assert.Equal(t, "responses_shaped_body", data.SkippedReason)
		})
	}
	t.Run("messages null counts as absent", func(t *testing.T) {
		b := `{"input":"hi","messages":null}`
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "", b)
		assert.Equal(t, b, got)
		assert.Equal(t, "responses_shaped_body", data.SkippedReason)
	})
	t.Run("input next to messages is a chat body", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "", `{"input":"x","messages":[{"role":"user","content":"hi"}]}`)
		assert.Equal(t, decisionInjected, data.Decision)
	})
	t.Run("required mode B rejects in enforce", func(t *testing.T) {
		pe := requirePluginError(t, execOpenAI(t, requiredModeBSettings(), body))
		assert.Equal(t, typeRequired, pe.Type)
	})
	t.Run("unscanned flag only with mode B", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "openai_responses", `{"input":"{template://x}"}`)
		assert.False(t, data.UnscannedTemplateReference)
	})
}

func execOpenAI(t *testing.T, settings map[string]any, body string) error {
	t.Helper()
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: &infracontext.RequestContext{Provider: "openai", Body: []byte(body)},
	})
	return err
}
