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
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strconv"
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
		{"files", "openai", "openai_files", "unsupported_format:openai_files"},
		{"cohere rerank", "cohere", "cohere_rerank", "unsupported_format:cohere_rerank"},
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
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), "openai", "openai_embeddings", plain)
		assert.Equal(t, plain, got)
		assert.False(t, data.UnscannedTemplateReference)
	})

	t.Run("properties are still stripped", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "be brief"), "openai", "openai_embeddings", `{"input":"hi","properties":{"a":"b"}}`)
		assert.JSONEq(t, `{"input":"hi"}`, got)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
	})

	t.Run("observe records the decision too", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeObserve, injectSettings("system", "merge", "be brief"), "openai", "openai_embeddings", body)
		assert.Equal(t, body, got)
		assert.Equal(t, decisionSkippedFormat, data.Decision)
	})
}

func TestExecuteShapeVetoesAreRejected(t *testing.T) {
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
			data := rejectedShape(t, injectSettings("system", "merge", "be brief"), tt.provider, "", tt.body)
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
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "google", "openai_embeddings", body)
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
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "google", "", body)
		assert.Equal(t, "non_canonical_key", data.SkippedReason, body)
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
		t.Run(name+" system is refused, not overwritten", func(t *testing.T) {
			body := `{"system":` + system + `,"messages":[{"role":"user","content":"hi"}]}`
			data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "anthropic", "", body)
			assert.Equal(t, reasonSystemUnreadable, data.SkippedReason)
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
		{"openai embeddings", "openai", "openai_embeddings", false, `{"input":"hi"}`, "unsupported_format:openai_embeddings", decisionSkippedFormat},
		{"cohere rerank", "cohere", "cohere_rerank", false, `{"query":"q"}`, "unsupported_format:cohere_rerank", decisionSkippedFormat},
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
	// The OpenAI chat adapter (and Mistral and OpenRouter, which delegate to it)
	// decodes input-without-messages as a Responses request, so it is edited as one.
	body := `{"model":"m","input":"hi"}`
	for _, provider := range []string{"openai", "azure", "groq", "deepseek", "xai", "openrouter", "mistral"} {
		t.Run(provider+" is edited as a Responses body", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), provider, "", body)
			assert.JSONEq(t, `{"model":"m","input":"hi","instructions":"INJ"}`, got)
			assert.Equal(t, decisionInjected, data.Decision)
		})
	}
	t.Run("the real chat adapter reads the injected text", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJECTED"), "openai", "openai", body)
		creq, err := adapter.NewRegistry().DecodeRequestFor([]byte(got), adapter.FormatOpenAI)
		require.NoError(t, err)
		assert.Contains(t, creq.System, "INJECTED")
		assert.Equal(t, []canonicalTurn{{"user", "hi"}}, canonicalTurns(creq))
	})
	t.Run("Mode B resolves a reference in input", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "openai", "", `{"input":"{template://bot@stable}"}`)
		assert.Equal(t, decisionRendered, data.Decision)
		assert.Contains(t, got, `"instructions":"You are a bot."`)
	})
	t.Run("messages null is a chat body for the adapter, so it is edited as one", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "", `{"input":"hi","messages":null}`)
		assert.Contains(t, got, `"messages":[{"role":"system","content":"INJ"}]`)
	})
	t.Run("cohere has no Responses detection, so input is just another field", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "cohere", "", body)
		assert.JSONEq(t, `{"model":"m","input":"hi","messages":[{"role":"system","content":"INJ"}]}`, got)
	})
	t.Run("input next to messages is a chat body", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "", `{"input":"x","messages":[{"role":"user","content":"hi"}]}`)
		assert.Equal(t, decisionInjected, data.Decision)
	})
	t.Run("a repeated key in a Responses-shaped body is rejected", func(t *testing.T) {
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "openai", "", `{"input":"a","input":"b"}`)
		assert.Equal(t, "ambiguous_responses_keys", data.SkippedReason)
	})
	t.Run("unscanned flag only with mode B", func(t *testing.T) {
		_, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "openai_embeddings", `{"input":"{template://x}"}`)
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

func TestResponsesModeASystem(t *testing.T) {
	tests := []struct {
		name       string
		onExisting string
		body       string
		want       string
	}{
		{"absent creates instructions", "merge", `{"model":"m","input":"hi"}`, `{"model":"m","input":"hi","instructions":"INJ"}`},
		{"merge appends", "merge", `{"instructions":"old","input":"hi"}`, `{"instructions":"old\n\nINJ","input":"hi"}`},
		{"replace overwrites", "replace", `{"instructions":"old","input":"hi"}`, `{"instructions":"INJ","input":"hi"}`},
		{"null instructions is absent", "merge", `{"instructions":null,"input":[]}`, `{"instructions":"INJ","input":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", tt.onExisting, "INJ"), "", "openai_responses", tt.body)
			assert.JSONEq(t, tt.want, got)
			assert.Equal(t, decisionInjected, data.Decision)
			assert.Equal(t, []string{"a"}, data.InjectedIDs)
			_, hasMessages := geminiOut(t, got)["messages"]
			assert.False(t, hasMessages)
		})
	}

	t.Run("source format wins over a chat provider", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "openai", "openai_responses", `{"input":"hi"}`)
		assert.JSONEq(t, `{"input":"hi","instructions":"INJ"}`, got)
	})
	t.Run("non-string instructions is unapplied", func(t *testing.T) {
		body := `{"instructions":{"x":1},"input":"hi"}`
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "", "openai_responses", body)
		assert.Equal(t, reasonInstructionsUnreadable, data.SkippedReason)
		assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonInstructionsUnreadable}}, data.Unapplied)
	})
}

func TestResponsesModeARolesAndInput(t *testing.T) {
	t.Run("user prepends an item to an array input", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "", "openai_responses",
			`{"input":[{"role":"user","content":"hi"},{"type":"function_call_output","call_id":"c","output":"x"}]}`)
		assert.JSONEq(t, `{"input":[{"type":"message","role":"user","content":"INJ"},{"role":"user","content":"hi"},{"type":"function_call_output","call_id":"c","output":"x"}]}`, got)
		assert.Equal(t, []string{"a"}, data.InjectedIDs)
	})
	t.Run("string input is converted to a user item when a prepend is needed", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("developer", "merge", "INJ"), "", "openai_responses", `{"input":"hi"}`)
		assert.JSONEq(t, `{"input":[{"type":"message","role":"developer","content":"INJ"},{"type":"message","role":"user","content":"hi"}]}`, got)
	})
	t.Run("string input is left alone for a system injection", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJ"), "", "openai_responses", `{"input":"hi"}`)
		assert.JSONEq(t, `{"input":"hi","instructions":"INJ"}`, got)
	})
	t.Run("absent input is created", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("assistant", "merge", "INJ"), "", "openai_responses", `{"model":"m"}`)
		assert.JSONEq(t, `{"model":"m","input":[{"type":"message","role":"assistant","content":"INJ"}]}`, got)
	})
	t.Run("tool role is unapplied", func(t *testing.T) {
		body := `{"input":"hi"}`
		got, data := runPlugin(t, policy.ModeEnforce, injectSettings("tool", "merge", "INJ"), "", "openai_responses", body)
		assert.Equal(t, body, got)
		assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonRoleUnsupportedResponses}}, data.Unapplied)
	})
	t.Run("input that is neither string nor array is skipped", func(t *testing.T) {
		body := `{"input":{"x":1}}`
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "", "openai_responses", body)
		assert.Equal(t, reasonInputUnreadable, data.SkippedReason)
	})
	t.Run("non canonical keys are vetoed", func(t *testing.T) {
		body := `{"Input":"hi"}`
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "", "openai_responses", body)
		assert.Equal(t, "non_canonical_key", data.SkippedReason)
	})
}

func TestResponsesModeB(t *testing.T) {
	t.Run("string input reference is rendered, system goes to instructions", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "", "openai_responses",
			`{"instructions":"keep","input":"{template://bot@stable}"}`)
		assert.JSONEq(t, `{"instructions":"keep\n\nYou are a bot.","input":[`+
			`{"type":"message","role":"assistant","content":"Hello"},{"type":"message","role":"user","content":"Go"}]}`, got)
		assert.Equal(t, decisionRendered, data.Decision)
		assert.Equal(t, "bot", data.ResolvedTemplate)
	})
	t.Run("message item with input_text parts", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "", "openai_responses",
			`{"input":[{"role":"user","content":"earlier"},{"role":"user","content":[{"type":"input_text","text":"{template://bot@stable}"}]}]}`)
		assert.Equal(t, decisionRendered, data.Decision)
		assert.Equal(t, 0, data.DiscardedMessages)
		assert.NotContains(t, got, "template://")
		assert.Contains(t, got, `"instructions":"You are a bot."`)
	})
	t.Run("bare input_text item", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"input":[{"type":"input_text","text":"{template://x}"}]}`))
		require.NoError(t, err)
		rb.shape = shapeResponses
		assert.Equal(t, []templateRef{{name: "x"}}, rb.findReferences())
	})
	t.Run("plain string fragment replaces input", func(t *testing.T) {
		settings := map[string]any{
			"named_templates": []any{map[string]any{"name": "p", "versions": []any{map[string]any{"labels": []any{"stable"}, "content": "Plain"}}}},
			"default_label":   "stable",
		}
		got, _ := runPlugin(t, policy.ModeEnforce, settings, "", "openai_responses", `{"input":"{template://p}"}`)
		assert.JSONEq(t, `{"input":"Plain"}`, got)
	})
	t.Run("Mode A replace runs after Mode B", func(t *testing.T) {
		settings := geminiModeBSettings()
		settings["inject_templates"] = []any{map[string]any{"id": "a", "position": "system", "role": "system", "content": "MODE-A", "on_existing_system": "replace"}}
		got, _ := runPlugin(t, policy.ModeEnforce, settings, "", "openai_responses", `{"instructions":"client","input":"{template://bot@stable}"}`)
		assert.Contains(t, got, `"instructions":"MODE-A"`)
	})
	t.Run("a missing template is rejected", func(t *testing.T) {
		_, err := New().Execute(context.Background(), appplugins.ExecInput{
			Mode:    policy.ModeEnforce,
			Config:  policy.PluginConfig{Settings: geminiModeBSettings()},
			Request: &infracontext.RequestContext{SourceFormat: "openai_responses", Body: []byte(`{"input":"{template://nope}"}`)},
		})
		assert.Equal(t, typeNotFound, requirePluginError(t, err).Type)
	})
	t.Run("required mode B with no reference rejects like any request", func(t *testing.T) {
		_, err := New().Execute(context.Background(), appplugins.ExecInput{
			Mode:    policy.ModeEnforce,
			Config:  policy.PluginConfig{Settings: requiredModeBSettings()},
			Request: &infracontext.RequestContext{SourceFormat: "openai_responses", Body: []byte(`{"input":"hi"}`)},
		})
		assert.Equal(t, typeRequired, requirePluginError(t, err).Type)
	})
}

func TestBedrockModeA(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
	tests := []struct {
		name       string
		onExisting string
		body       string
		want       string
	}{
		{"absent creates a block", "merge", body, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"system":[{"text":"INJ"}]}`},
		{"merge appends and keeps cachePoint blocks", "merge",
			`{"system":[{"text":"old"},{"cachePoint":{"type":"default"}}],"messages":[]}`,
			`{"system":[{"text":"old"},{"cachePoint":{"type":"default"}},{"text":"INJ"}],"messages":[]}`},
		{"replace leaves one block", "replace", `{"system":[{"text":"old"},{"text":"older"}],"messages":[]}`, `{"system":[{"text":"INJ"}],"messages":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", tt.onExisting, "INJ"), "bedrock", "", tt.body)
			assert.JSONEq(t, tt.want, got)
			assert.Equal(t, []string{"a"}, data.InjectedIDs)
			assert.Equal(t, decisionInjected, data.Decision)
		})
	}
	t.Run("user merges into the first user turn so roles keep alternating", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "bedrock", "", body)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"INJ"},{"text":"hi"}]}]}`, got)
	})
	t.Run("user creates a turn when the first one is the assistant's or there is none", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "bedrock", "", `{"messages":[{"role":"assistant","content":[{"text":"a"}]}]}`)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"INJ"}]},{"role":"assistant","content":[{"text":"a"}]}]}`, got)
		got, _ = runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "bedrock", "", `{"messages":[]}`)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"INJ"}]}]}`, got)
	})
	t.Run("user keeps unknown fields of the first turn", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "bedrock", "", `{"messages":[{"role":"user","extra":1,"content":[{"image":{"format":"png"}}]}]}`)
		assert.JSONEq(t, `{"messages":[{"role":"user","extra":1,"content":[{"text":"INJ"},{"image":{"format":"png"}}]}]}`, got)
	})
	t.Run("blank content is unapplied", func(t *testing.T) {
		for _, role := range []string{"system", "user"} {
			rb, err := decodeBody([]byte(body))
			require.NoError(t, err)
			rb.shape = shapeBedrock
			applied, reason := rb.injectSystem(onExistingMerge, role, "  \n ")
			assert.False(t, applied)
			assert.Equal(t, reasonEmptyContent, reason)
			assert.False(t, rb.dirty())
		}
	})
	for _, role := range []string{"assistant", "developer", "tool"} {
		t.Run(role+" is unapplied", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings(role, "merge", "INJ"), "bedrock", "", body)
			assert.Equal(t, body, got)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonRoleUnsupportedBedrock}}, data.Unapplied)
		})
	}
	t.Run("unreadable system is refused", func(t *testing.T) {
		b := `{"system":"plain","messages":[]}`
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "bedrock", "", b)
		assert.Equal(t, reasonBedrockSystemBad, data.SkippedReason)
		assert.Equal(t, reasonBedrockSystemBad, data.Unapplied[0].Reason)
	})
	t.Run("opaque messages are refused", func(t *testing.T) {
		data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "bedrock", "", `{"messages":"x"}`)
		assert.Equal(t, reasonMessagesNotArray, data.SkippedReason)
	})
}

func TestBedrockModeB(t *testing.T) {
	t.Run("reference in a text block, system fragment merged into system blocks", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeEnforce, convoSettings(), "bedrock", "",
			`{"system":[{"text":"keep"}],"messages":[{"role":"user","content":[{"text":"earlier"}]},{"role":"user","content":[{"text":"{template://convo@stable}"}]}]}`)
		assert.JSONEq(t, `{"system":[{"text":"keep"},{"text":"You are a bot."}],"messages":[`+
			`{"role":"user","content":[{"text":"Q"}]},{"role":"assistant","content":[{"text":"A"}]},{"role":"user","content":[{"text":"Go"}]}]}`, got)
		assert.Equal(t, decisionRendered, data.Decision)
		assert.NotContains(t, got, "template://")
	})
	t.Run("plain string fragment is one user turn", func(t *testing.T) {
		settings := map[string]any{
			"named_templates": []any{map[string]any{"name": "p", "versions": []any{map[string]any{"labels": []any{"stable"}, "content": "Plain"}}}},
			"default_label":   "stable",
		}
		got, _ := runPlugin(t, policy.ModeEnforce, settings, "bedrock", "", `{"messages":[{"role":"user","content":[{"text":"{template://p}"}]}]}`)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"Plain"}]}]}`, got)
	})
	t.Run("adjacent same-role turns are coalesced", func(t *testing.T) {
		settings := map[string]any{
			"named_templates": []any{map[string]any{"name": "c", "versions": []any{map[string]any{"labels": []any{"stable"},
				"content": `[{"role":"user","content":"a"},{"role":"developer","content":"b"},{"role":"assistant","content":"c"}]`}}}},
			"default_label": "stable",
		}
		got, _ := runPlugin(t, policy.ModeEnforce, settings, "bedrock", "", `{"messages":[{"role":"user","content":[{"text":"{template://c}"}]}]}`)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"a"},{"text":"b"}]},{"role":"assistant","content":[{"text":"c"}]}]}`, got)
	})
	t.Run("a fragment that opens with the assistant is a clear render error", func(t *testing.T) {
		_, err := New().Execute(context.Background(), appplugins.ExecInput{
			Mode:    policy.ModeEnforce,
			Config:  policy.PluginConfig{Settings: geminiModeBSettings()},
			Request: &infracontext.RequestContext{Provider: "bedrock", Body: []byte(`{"messages":[{"role":"user","content":[{"text":"{template://bot@stable}"}]}]}`)},
		})
		pe := requirePluginError(t, err)
		assert.Equal(t, typeRenderFailed, pe.Type)
		assert.Contains(t, pe.Message, "open with a user turn")
	})
	t.Run("non-text blocks are not scanned", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"1","content":[{"text":"{template://leak}"}]}},{"text":"{template://real}"}]}]}`))
		require.NoError(t, err)
		rb.shape = shapeBedrock
		assert.Equal(t, []templateRef{{name: "real"}}, rb.findReferences())
	})
}

func TestAnthropicModeBFragmentSystem(t *testing.T) {
	body := func(system string) string {
		return `{` + system + `"messages":[{"role":"user","content":"{template://bot@stable}"}]}`
	}
	wantMsgs := `[{"role":"assistant","content":"Hello"},{"role":"user","content":[{"type":"text","text":"Go"}]}]`

	t.Run("no system creates one and no system message reaches messages", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "anthropic", "", body(""))
		assert.JSONEq(t, `{"system":"You are a bot.","messages":`+wantMsgs+`}`, got)
	})
	t.Run("string system is merged", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "anthropic", "", body(`"system":"keep",`))
		assert.JSONEq(t, `{"system":"keep\n\nYou are a bot.","messages":`+wantMsgs+`}`, got)
	})
	t.Run("block system gets a text block", func(t *testing.T) {
		got, _ := runPlugin(t, policy.ModeEnforce, geminiModeBSettings(), "anthropic", "", body(`"system":[{"type":"text","text":"keep","cache_control":{"type":"ephemeral"}}],`))
		assert.JSONEq(t, `{"system":[{"type":"text","text":"keep","cache_control":{"type":"ephemeral"}},{"type":"text","text":"You are a bot."}],"messages":`+wantMsgs+`}`, got)
	})
}

func convoSettings() map[string]any {
	return map[string]any{
		"named_templates": []any{map[string]any{
			"name": "convo",
			"versions": []any{map[string]any{
				"labels":  []any{"stable"},
				"content": `[{"role":"system","content":"You are a bot."},{"role":"user","content":"Q"},{"role":"assistant","content":"A"},{"role":"user","content":"Go"}]`,
			}},
		}},
		"default_label": "stable",
	}
}

type canonicalTurn struct{ role, text string }

func canonicalTurns(creq *adapter.CanonicalRequest) []canonicalTurn {
	out := make([]canonicalTurn, 0, len(creq.Messages))
	for _, m := range creq.Messages {
		out = append(out, canonicalTurn{role: m.Role, text: m.Content})
	}
	return out
}

// The gateway decodes the plugin's output with the real adapters, so what the
// plugin wrote must come out as the same system prompt and conversation the
// adapter reads, for every format it edits.
func TestOutputSurvivesRealAdapterDecode(t *testing.T) {
	registry := adapter.NewRegistry()
	formats := []struct {
		name    string
		source  string
		format  adapter.Format
		body    string
		refBody string
	}{
		{"openai", "openai", adapter.FormatOpenAI,
			`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
			`{"model":"m","messages":[{"role":"user","content":"{template://convo@stable}"}]}`},
		{"anthropic", "anthropic", adapter.FormatAnthropic,
			`{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`,
			`{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"{template://convo@stable}"}]}`},
		{"gemini", "google", adapter.FormatGemini,
			`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`,
			`{"contents":[{"role":"user","parts":[{"text":"{template://convo@stable}"}]}]}`},
		{"responses", "openai_responses", adapter.FormatOpenAIResponses,
			`{"model":"m","input":[{"role":"user","content":"hi"}]}`,
			`{"model":"m","input":"{template://convo@stable}"}`},
		{"bedrock", "bedrock", adapter.FormatBedrock,
			`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
			`{"messages":[{"role":"user","content":[{"text":"{template://convo@stable}"}]}]}`},
	}
	for _, f := range formats {
		decode := func(t *testing.T, raw string) *adapter.CanonicalRequest {
			t.Helper()
			creq, err := registry.DecodeRequestFor([]byte(raw), f.format)
			require.NoError(t, err)
			return creq
		}
		t.Run(f.name+" system injection", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("system", "merge", "INJECTED"), "", f.source, f.body)
			require.Equal(t, decisionInjected, data.Decision)
			creq := decode(t, got)
			assert.Contains(t, creq.System, "INJECTED")
			assert.Equal(t, []canonicalTurn{{"user", "hi"}}, canonicalTurns(creq), "the conversation is untouched")

			encoded, err := registry.AdaptRequest([]byte(got), f.format, adapter.FormatOpenAI)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), "INJECTED")
		})
		t.Run(f.name+" user injection", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJECTED"), "", f.source, f.body)
			require.Equal(t, decisionInjected, data.Decision)
			creq := decode(t, got)
			require.NotEmpty(t, creq.Messages)
			assert.Equal(t, "user", creq.Messages[0].Role)
			var all string
			for _, m := range creq.Messages {
				all += m.Content + "|"
			}
			assert.Contains(t, all, "INJECTED")
			assert.Contains(t, all, "hi")
		})
		t.Run(f.name+" Mode B fragment with a system message", func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, convoSettings(), "", f.source, f.refBody)
			require.Equal(t, decisionRendered, data.Decision)
			creq := decode(t, got)
			assert.Contains(t, creq.System, "You are a bot.")
			assert.Equal(t, []canonicalTurn{{"user", "Q"}, {"assistant", "A"}, {"user", "Go"}}, canonicalTurns(creq))
			assert.NotContains(t, got, "template://")
		})
	}

	t.Run("bedrock output alternates roles in the raw body", func(t *testing.T) {
		for _, body := range []string{
			`{"messages":[{"role":"user","content":[{"text":"hi"}]},{"role":"assistant","content":[{"text":"a"}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"text":"a"}]}]}`,
			`{"messages":[]}`,
		} {
			got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJECTED"), "bedrock", "", body)
			creq, err := registry.DecodeRequestFor([]byte(got), adapter.FormatBedrock)
			require.NoError(t, err)
			for i := 1; i < len(creq.Messages); i++ {
				assert.NotEqual(t, creq.Messages[i-1].Role, creq.Messages[i].Role, got)
			}
		}
	})
}

func TestNonCanonicalKeysAreVetoedOnEveryShape(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		sourceFormat string
		body         string
	}{
		{"responses long s", "", "openai_responses", `{"inſtructions":"client","input":"hi"}`},
		{"responses case", "", "openai_responses", `{"Instructions":"client","input":"hi"}`},
		{"bedrock long s system", "", "bedrock", `{"ſystem":[{"text":"client"}],"messages":[]}`},
		{"bedrock long s messages", "", "bedrock", `{"meſsages":[]}`},
		{"openai Messages", "openai", "", `{"Messages":[{"role":"user","content":"hi"}]}`},
		{"openai System", "openai", "", `{"System":"client","messages":[]}`},
		{"anthropic System", "anthropic", "", `{"System":"client","messages":[]}`},
		{"gemini SYSTEM_INSTRUCTION", "google", "", `{"SYSTEM_INSTRUCTION":{"parts":[{"text":"client"}]},"contents":[]}`},
		{"cohere Messages", "cohere", "", `{"Messages":[{"role":"user","content":"hi"}]}`},
		{"mistral System", "mistral", "", `{"System":"client","messages":[]}`},
		{"gemini SystemInstruction", "google", "", `{"SystemInstruction":{"parts":[{"text":"client"}]},"contents":[]}`},
		{"gemini long s", "google", "", `{"ſystemInstruction":{"parts":[]},"contents":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := rejectedShape(t, injectSettings("system", "merge", "INJ"), tt.provider, tt.sourceFormat, tt.body)
			assert.Equal(t, "non_canonical_key", data.SkippedReason)
			assert.Empty(t, data.InjectedIDs)
		})
	}
}

func TestDuplicateKeysAreVetoed(t *testing.T) {
	for name, tc := range map[string]struct{ source, body, reason string }{
		"responses": {"openai_responses", `{"input":"a","input":"b"}`, "ambiguous_responses_keys"},
		"bedrock":   {"bedrock", `{"messages":[],"messages":[{"role":"user","content":[{"text":"x"}]}]}`, "ambiguous_bedrock_keys"},
	} {
		t.Run(name, func(t *testing.T) {
			data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "", tc.source, tc.body)
			assert.Equal(t, tc.reason, data.SkippedReason)
		})
	}
}

func TestAmbiguousAfterEditIsRejected(t *testing.T) {
	// A repeated key inside a message is only visible once the whole edited body
	// is checked: the plugin cannot tell which copy the upstream would read.
	body := `{"properties":{"a":"b"},"messages":[{"role":"user","content":"hi","content":"x"}]}`
	data := rejectedShape(t, injectSettings("system", "merge", "INJ"), "openai", "", body)
	assert.Equal(t, "ambiguous_after_edit", data.SkippedReason)
	assert.Empty(t, data.InjectedIDs)

	t.Run("observe forwards the original untouched", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeObserve, injectSettings("system", "merge", "INJ"), "openai", "", body)
		assert.NotContains(t, got, "INJ")
		assert.Equal(t, decisionObserved, data.Decision)
	})

	t.Run("required mode B gets the shape error too", func(t *testing.T) {
		body := `{"tools":[{"type":"function","function":{"name":"a","name":"b"}}],"messages":[{"role":"user","content":"{template://bot@stable}"}]}`
		data := rejectedShape(t, requiredModeBSettings(), "openai", "", body)
		assert.Equal(t, "ambiguous_after_edit", data.SkippedReason)
	})
}

func TestResponsesScanReadsAnyStringTextPart(t *testing.T) {
	rb, err := decodeBody([]byte(`{"input":[` +
		`{"role":"user","content":[{"type":"output_text","text":"{template://a}"},{"type":"input_text","text":7},{"type":"text","text":"{template://a}"}]},` +
		`{"type":"input_text","text":{"x":1}},` +
		`{"role":"user","content":"{template://a}"}]}`))
	require.NoError(t, err)
	rb.shape = shapeResponses
	assert.Equal(t, []templateRef{{name: "a"}, {name: "a"}, {name: "a"}}, rb.findReferences(),
		"a part with a non-string text is skipped on its own, not the whole item")
}

func fragmentSettings(content string) map[string]any {
	return map[string]any{
		"named_templates": []any{map[string]any{"name": "f", "versions": []any{map[string]any{"labels": []any{"stable"}, "content": content}}}},
		"default_label":   "stable",
	}
}

func execRender(t *testing.T, settings map[string]any, provider, sourceFormat, body string) *appplugins.PluginError {
	t.Helper()
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: &infracontext.RequestContext{Provider: provider, SourceFormat: sourceFormat, Body: []byte(body)},
	})
	return requirePluginError(t, err)
}

func TestBedrockFirstMessageKeyCasing(t *testing.T) {
	for name, body := range map[string]string{
		"Role":    `{"messages":[{"Role":"user","content":[{"text":"hi"}]}]}`,
		"Content": `{"messages":[{"role":"user","Content":[{"text":"hi"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			data := rejectedShape(t, injectSettings("user", "merge", "INJ"), "bedrock", "", body)
			assert.Equal(t, reasonBedrockMessageBad, data.SkippedReason)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: reasonBedrockMessageBad}}, data.Unapplied)
		})
	}
}

func TestEmptyConversationAfterRender(t *testing.T) {
	for name, tc := range map[string]struct{ source, body, content string }{
		"bedrock system only":   {"bedrock", `{"messages":[{"role":"user","content":[{"text":"{template://f}"}]}]}`, `[{"role":"system","content":"S"}]`},
		"bedrock blank turns":   {"bedrock", `{"messages":[{"role":"user","content":[{"text":"{template://f}"}]}]}`, `[{"role":"user","content":"  "},{"role":"assistant","content":null}]`},
		"responses system only": {"openai_responses", `{"input":"{template://f}"}`, `[{"role":"system","content":"S"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			pe := execRender(t, fragmentSettings(tc.content), "", tc.source, tc.body)
			assert.Equal(t, typeRenderFailed, pe.Type)
			assert.Equal(t, "rendered template has no conversation turns", pe.Message)
		})
	}
}

func TestResponsesScanPrecedenceMirrorsTheAdapter(t *testing.T) {
	scan := func(input string) []templateRef {
		rb, err := decodeBody([]byte(`{"input":` + input + `}`))
		require.NoError(t, err)
		rb.shape = shapeResponses
		return rb.findReferences()
	}
	t.Run("an item with a role is read through content, not text", func(t *testing.T) {
		assert.Equal(t, []templateRef{{name: "b"}}, scan(`[{"role":"user","type":"input_text","text":"{template://a}","content":"{template://b}"}]`))
		assert.Empty(t, scan(`[{"role":"user","type":"input_text","text":"{template://a}","content":"plain"}]`))
	})
	t.Run("text is read only for a role-less input_text item", func(t *testing.T) {
		assert.Equal(t, []templateRef{{name: "a"}}, scan(`[{"type":"input_text","text":"{template://a}","content":"{template://b}"}]`))
		assert.Empty(t, scan(`[{"type":"output_text","text":"{template://a}"}]`))
	})
}

func TestUnreadableClientSystemInModeBIsAShapeRejection(t *testing.T) {
	const frag = `[{"role":"system","content":"S"},{"role":"user","content":"Go"}]`
	tests := []struct {
		name, provider, source, body, reason string
	}{
		{"anthropic", "anthropic", "", `{"system":{"x":1},"messages":[{"role":"user","content":"{template://f}"}]}`, reasonSystemUnreadable},
		{"responses", "", "openai_responses", `{"instructions":{"x":1},"input":"{template://f}"}`, reasonInstructionsUnreadable},
		{"bedrock", "bedrock", "", `{"system":"plain","messages":[{"role":"user","content":[{"text":"{template://f}"}]}]}`, reasonBedrockSystemBad},
		{"gemini", "google", "", `{"systemInstruction":"plain","contents":[{"role":"user","parts":[{"text":"{template://f}"}]}]}`, reasonSystemInstructionBad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := rejectedShape(t, fragmentSettings(frag), tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.reason, data.SkippedReason)
			assert.Empty(t, data.ResolvedTemplate)
			assert.Empty(t, data.InjectedIDs)
		})
	}
	t.Run("an operator-side render error stays a 500", func(t *testing.T) {
		pe := execRender(t, fragmentSettings(`[{"role":"assistant","content":"x"}]`), "bedrock", "", `{"messages":[{"role":"user","content":[{"text":"{template://f}"}]}]}`)
		assert.Equal(t, typeRenderFailed, pe.Type)
		assert.Equal(t, http.StatusInternalServerError, pe.StatusCode)
	})
}

func TestRejectionEventCarriesNoAppliedState(t *testing.T) {
	// The first template (role user) applies; the second (role system) hits the
	// client's unreadable system field.
	settings := map[string]any{}
	settings["inject_templates"] = []any{
		map[string]any{"id": "ok", "position": "system", "role": "user", "content": "A", "on_existing_system": "merge"},
		map[string]any{"id": "bad", "position": "system", "role": "system", "content": "B", "on_existing_system": "merge"},
	}
	data := rejectedShape(t, settings, "anthropic", "", `{"system":{"x":1},"messages":[{"role":"user","content":"{template://x}"}]}`)
	assert.Equal(t, reasonSystemUnreadable, data.SkippedReason)
	assert.Equal(t, []unappliedInjection{{ID: "bad", Reason: reasonSystemUnreadable}}, data.Unapplied)
	assert.Empty(t, data.InjectedIDs, "the request was refused, so nothing was injected")
	assert.Empty(t, data.ResolvedTemplate)
	assert.Zero(t, data.DiscardedMessages)
	assert.Empty(t, data.DroppedClientVariables)
}

func TestBedrockModeBWithModeAUser(t *testing.T) {
	settings := convoSettings()
	settings["inject_templates"] = injectSettings("user", "merge", "INJ")["inject_templates"]
	got, _ := runPlugin(t, policy.ModeEnforce, settings, "bedrock", "", `{"messages":[{"role":"user","content":[{"text":"{template://convo@stable}"}]}]}`)
	assert.JSONEq(t, `{"system":[{"text":"You are a bot."}],"messages":[`+
		`{"role":"user","content":[{"text":"INJ"},{"text":"Q"}]},{"role":"assistant","content":[{"text":"A"}]},{"role":"user","content":[{"text":"Go"}]}]}`, got)
}

func TestBedrockAlternationOnShortConversations(t *testing.T) {
	registry := adapter.NewRegistry()
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"empty", `{"messages":[]}`, []string{"user"}},
		{"assistant only", `{"messages":[{"role":"assistant","content":[{"text":"a"}]}]}`, []string{"user", "assistant"}},
		{"single user", `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`, []string{"user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := runPlugin(t, policy.ModeEnforce, injectSettings("user", "merge", "INJ"), "bedrock", "", tt.body)
			creq, err := registry.DecodeRequestFor([]byte(got), adapter.FormatBedrock)
			require.NoError(t, err)
			var roles []string
			for _, m := range creq.Messages {
				roles = append(roles, m.Role)
			}
			assert.Equal(t, tt.want, roles)
		})
	}
}

// rejectedShape runs the plugin in enforce mode and asserts the request is
// refused with 400 unsupported_request_shape, with the event keeping the skip
// decision. It returns the event.
func rejectedShape(t *testing.T, settings map[string]any, provider, sourceFormat, body string) PromptTemplateData {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: &infracontext.RequestContext{Provider: provider, SourceFormat: sourceFormat, Body: []byte(body)},
		Event:   metrics.NewEventContext(span),
	})
	pe := requirePluginError(t, err)
	assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
	assert.Equal(t, typeUnsupportedShape, pe.Type)
	data, ok := span.PluginAttrsCopy().Extras.(PromptTemplateData)
	require.True(t, ok)
	assert.Equal(t, decisionSkippedShape, data.Decision)
	assert.NotEmpty(t, data.SkippedReason)
	assert.Contains(t, pe.Message, "("+data.SkippedReason+")")
	return data
}

// Every way a chat body can be unfit to edit, as (provider, source format, body, reason).
var shapeRejections = []struct {
	name, provider, source, body, reason string
}{
	{"messages not an array", "openai", "", `{"messages":"x"}`, reasonMessagesNotArray},
	{"gemini systemInstruction string", "google", "", `{"systemInstruction":"x","contents":[]}`, reasonSystemInstructionBad},
	{"gemini systemInstruction array", "google", "", `{"system_instruction":[],"contents":[]}`, reasonSystemInstructionBad},
	{"non canonical key", "openai", "", `{"Messages":[]}`, "non_canonical_key"},
	{"gemini ambiguous", "google", "", `{"contents":[],"systemInstruction":{},"system_instruction":{}}`, "ambiguous_gemini_keys"},
	{"gemini contents not array", "google", "", `{"contents":"x"}`, reasonContentsNotArray},
	{"responses ambiguous", "", "openai_responses", `{"input":"a","input":"b"}`, "ambiguous_responses_keys"},
	{"responses input unreadable", "", "openai_responses", `{"input":{"x":1}}`, reasonInputUnreadable},
	{"bedrock ambiguous", "", "bedrock", `{"messages":[],"messages":[]}`, "ambiguous_bedrock_keys"},
	{"bedrock messages not array", "", "bedrock", `{"messages":"x"}`, reasonMessagesNotArray},
	{"ambiguous after edit", "openai", "", `{"messages":[{"role":"user","content":"a","content":"b"}]}`, "ambiguous_after_edit"},
}

func TestEveryShapeRejectionInEnforce(t *testing.T) {
	for _, tt := range shapeRejections {
		t.Run(tt.name+" mode A only", func(t *testing.T) {
			data := rejectedShape(t, injectSettings("system", "merge", "INJ"), tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.reason, data.SkippedReason)
		})
		t.Run(tt.name+" required mode B", func(t *testing.T) {
			if tt.reason == "ambiguous_after_edit" {
				t.Skip("Mode B replaces the conversation, so the repeated key is gone; covered with a tools case")
			}
			data := rejectedShape(t, requiredModeBSettings(), tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.reason, data.SkippedReason)
		})
		t.Run(tt.name+" permissive mode B", func(t *testing.T) {
			if tt.reason == "ambiguous_after_edit" {
				t.Skip("Mode B replaces the conversation, so the repeated key is gone; covered with a tools case")
			}
			settings := geminiModeBSettings()
			settings["allow_untemplated_requests"] = true
			data := rejectedShape(t, settings, tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.reason, data.SkippedReason)
		})
		t.Run(tt.name+" observe never blocks", func(t *testing.T) {
			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			res, err := New().Execute(context.Background(), appplugins.ExecInput{
				Mode:    policy.ModeObserve,
				Config:  policy.PluginConfig{Settings: requiredModeBSettings()},
				Request: &infracontext.RequestContext{Provider: tt.provider, SourceFormat: tt.source, Body: []byte(tt.body)},
				Event:   metrics.NewEventContext(span),
			})
			require.NoError(t, err)
			assert.Nil(t, res.RequestBody)
		})
	}
}

func TestUnappliedCausesSplitClientFromOperator(t *testing.T) {
	// Client body: refused. Each row is a request the client shaped.
	clientBody := []struct {
		name, role, provider, source, body, reason string
	}{
		{"anthropic system object", "system", "anthropic", "", `{"system":{},"messages":[]}`, reasonSystemUnreadable},
		{"responses instructions object", "system", "", "openai_responses", `{"instructions":{},"input":"hi"}`, reasonInstructionsUnreadable},
		{"bedrock system string", "system", "bedrock", "", `{"system":"x","messages":[]}`, reasonBedrockSystemBad},
		{"bedrock first message", "user", "bedrock", "", `{"messages":[{"Role":"user","content":[]}]}`, reasonBedrockMessageBad},
	}
	for _, tt := range clientBody {
		t.Run("client: "+tt.name, func(t *testing.T) {
			data := rejectedShape(t, injectSettings(tt.role, "merge", "INJ"), tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.reason, data.SkippedReason)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: tt.reason}}, data.Unapplied)
		})
	}

	// Operator config: forwarded with the reason recorded.
	operator := []struct {
		name, role, provider, source, body, reason string
	}{
		{"gemini assistant", "assistant", "google", "", `{"contents":[]}`, reasonRoleUnsupportedGemini},
		{"anthropic developer", "developer", "anthropic", "", `{"messages":[]}`, reasonRoleUnsupportedAnthropic},
		{"responses tool", "tool", "", "openai_responses", `{"input":"hi"}`, reasonRoleUnsupportedResponses},
		{"bedrock assistant", "assistant", "bedrock", "", `{"messages":[]}`, reasonRoleUnsupportedBedrock},
	}
	for _, tt := range operator {
		t.Run("operator: "+tt.name, func(t *testing.T) {
			got, data := runPlugin(t, policy.ModeEnforce, injectSettings(tt.role, "merge", "INJ"), tt.provider, tt.source, tt.body)
			assert.Equal(t, tt.body, got)
			assert.Equal(t, []unappliedInjection{{ID: "a", Reason: tt.reason}}, data.Unapplied)
			assert.NotEqual(t, decisionSkippedShape, data.Decision)
		})
	}
	t.Run("operator: empty_content", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[]}`))
		require.NoError(t, err)
		rb.shape = shapeBedrock
		applied, reason := rb.injectSystem(onExistingMerge, roleSystem, " ")
		assert.False(t, applied)
		_, blocked := blockingUnapplied([]unappliedInjection{{ID: "a", Reason: reason}})
		assert.False(t, blocked)
	})

	t.Run("an unknown reason fails closed", func(t *testing.T) {
		_, blocked := blockingUnapplied([]unappliedInjection{{ID: "a", Reason: "something_new"}})
		assert.True(t, blocked)
	})
	t.Run("observe never blocks on a client-body reason", func(t *testing.T) {
		got, data := runPlugin(t, policy.ModeObserve, injectSettings("system", "merge", "INJ"), "anthropic", "", `{"system":{},"messages":[]}`)
		assert.Equal(t, `{"system":{},"messages":[]}`, got)
		assert.Equal(t, decisionObserved, data.Decision)
	})
}

// shapeOnlyReasons are reason constants that never come out of injectSystem,
// so they have no unapplied cause. None today.
var shapeOnlyReasons = map[string]bool{}

// A new reason constant must be classified, or the split between client and
// operator causes silently defaults.
func TestEveryReasonConstantIsClassified(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	require.NoError(t, err)
	var found []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if !strings.HasPrefix(name.Name, "reason") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						value, err := strconv.Unquote(lit.Value)
						require.NoError(t, err)
						found = append(found, value)
						_, classified := unappliedCauses[value]
						assert.True(t, classified || shapeOnlyReasons[value], "reason %s (%q) is not in unappliedCauses", name.Name, value)
					}
				}
			}
		}
	}
	assert.GreaterOrEqual(t, len(found), 10, "the parse found too few reason constants to trust")
}
