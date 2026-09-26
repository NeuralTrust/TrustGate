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

package adapter

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const chatOptionsSchema = `{"name":"answer","strict":true,"schema":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}}`

const chatOptionsBody = `{
	"model":"m",
	"seed":42,
	"parallel_tool_calls":true,
	"response_format":{"type":"json_schema","json_schema":` + chatOptionsSchema + `},
	"tools":[{"type":"function","function":{"name":"get_weather","parameters":{"type":"object","properties":{}}}}],
	"messages":[{"role":"user","content":"hi"}]
}`

const chatOptionsFormat = `{"type":"json_schema","json_schema":` + chatOptionsSchema + `}`

func TestAdaptRequest_OpenAIChatOptionsStayWithinWhatEachTargetAccepts(t *testing.T) {
	t.Parallel()

	const absent = ""
	tests := []struct {
		name        string
		source      Format
		target      Format
		provider    string
		passthrough bool
		want        map[string]string
		nowhere     []string
	}{
		{
			name:     "mistral takes random_seed, parallel_tool_calls and json_schema",
			source:   FormatOpenAI,
			target:   FormatMistral,
			provider: provider.Mistral,
			want: map[string]string{
				"random_seed":         `42`,
				"seed":                absent,
				"parallel_tool_calls": `true`,
				"response_format":     chatOptionsFormat,
			},
		},
		{
			name:     "groq never gets the caller's parallel_tool_calls",
			source:   FormatOpenAI,
			target:   FormatGroq,
			provider: provider.Groq,
			want: map[string]string{
				"seed":                `42`,
				"parallel_tool_calls": `false`,
				"response_format":     chatOptionsFormat,
			},
		},
		{
			name:     "openrouter takes every option",
			source:   FormatOpenAI,
			target:   FormatOpenRouter,
			provider: provider.OpenRouter,
			want: map[string]string{
				"seed":                `42`,
				"parallel_tool_calls": `true`,
				"response_format":     chatOptionsFormat,
			},
		},
		{
			name:     "deepseek re-encoded from groq drops every option",
			source:   FormatGroq,
			target:   FormatDeepSeek,
			provider: provider.DeepSeek,
			want: map[string]string{
				"seed":                absent,
				"parallel_tool_calls": absent,
				"response_format":     absent,
			},
		},
		{
			name:     "responses inlines the json_schema and drops seed",
			source:   FormatOpenAI,
			target:   FormatOpenAIResponses,
			provider: provider.OpenAI,
			want: map[string]string{
				"seed":                absent,
				"parallel_tool_calls": absent,
				"response_format":     absent,
				"text":                `{"format":{"type":"json_schema","name":"answer","strict":true,"schema":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}}}`,
			},
		},
		{name: "anthropic", source: FormatOpenAI, target: FormatAnthropic, provider: provider.Anthropic, nowhere: chatOptionKeys},
		{name: "gemini", source: FormatOpenAI, target: FormatGemini, provider: provider.Google, nowhere: chatOptionKeys},
		{name: "vertex", source: FormatOpenAI, target: FormatVertex, provider: provider.Vertex, nowhere: chatOptionKeys},
		{name: "bedrock", source: FormatOpenAI, target: FormatBedrock, provider: provider.Bedrock, nowhere: chatOptionKeys},
		{name: "cohere", source: FormatOpenAI, target: FormatCohere, provider: provider.Cohere, nowhere: chatOptionKeys},
		{name: "openai", source: FormatOpenAI, target: FormatOpenAI, provider: provider.OpenAI, passthrough: true},
		{name: "azure", source: FormatOpenAI, target: FormatAzure, provider: provider.Azure, passthrough: true},
		{name: "xai", source: FormatOpenAI, target: FormatXAI, provider: provider.XAI, passthrough: true},
		{name: "cerebras", source: FormatOpenAI, target: FormatOpenAI, provider: provider.Cerebras, passthrough: true},
		{name: "openai_compatible", source: FormatOpenAI, target: FormatOpenAI, provider: provider.OpenAICompatible, passthrough: true},
		{name: "deepseek from openai", source: FormatOpenAI, target: FormatDeepSeek, provider: provider.DeepSeek, passthrough: true},
	}

	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := reg.AdaptRequestForProvider([]byte(chatOptionsBody), tt.source, tt.target, tt.provider, "")
			require.NoError(t, err)
			if tt.passthrough {
				assert.JSONEq(t, chatOptionsBody, string(out), "the caller's body is forwarded as sent")
				return
			}
			out = NormalizeRequestForProvider(tt.provider, tt.target, out)

			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &fields), "%s", out)
			for key, want := range tt.want {
				got, has := fields[key]
				if want == absent {
					assert.False(t, has, "%s must not reach %s: %s", key, tt.target, out)
					continue
				}
				require.True(t, has, "%s missing for %s: %s", key, tt.target, out)
				assert.JSONEq(t, want, string(got), key)
			}
			for _, key := range tt.nowhere {
				assert.False(t, hasJSONKey(t, out, key), "%s must not reach %s: %s", key, tt.target, out)
			}
		})
	}
}

var chatOptionKeys = []string{"seed", "random_seed", "parallel_tool_calls", "response_format", "json_schema"}

func hasJSONKey(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(body, &v))
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if k == key || walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range x {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

func TestDecodeCompletionsRequest_LenientSeedAndParallelToolCalls(t *testing.T) {
	t.Parallel()

	seed := func(n int64) *int64 { return &n }
	tests := []struct {
		name     string
		seed     string
		parallel string
		wantSeed *int64
		wantPar  *bool
	}{
		{name: "integer", seed: `42`, parallel: `true`, wantSeed: seed(42), wantPar: boolPtr(true)},
		{name: "integral float", seed: `42.0`, parallel: `false`, wantSeed: seed(42), wantPar: boolPtr(false)},
		{name: "exponent", seed: `1e3`, wantSeed: seed(1000)},
		{name: "negative", seed: `-7`, wantSeed: seed(-7)},
		{name: "fractional seed is dropped", seed: `42.5`},
		{name: "out of range seed is dropped", seed: `1e30`},
		{name: "string seed is dropped", seed: `"42"`},
		{name: "bool seed is dropped", seed: `true`},
		{name: "object seed is dropped", seed: `{"v":1}`},
		{name: "null values are dropped", seed: `null`, parallel: `null`},
		{name: "non-bool parallel_tool_calls is dropped", seed: `1`, parallel: `"yes"`, wantSeed: seed(1)},
		{name: "numeric parallel_tool_calls is dropped", parallel: `1`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := map[string]json.RawMessage{
				"model":    json.RawMessage(`"m"`),
				"messages": json.RawMessage(`[{"role":"user","content":"hi"}]`),
			}
			if tt.seed != "" {
				body["seed"] = json.RawMessage(tt.seed)
			}
			if tt.parallel != "" {
				body["parallel_tool_calls"] = json.RawMessage(tt.parallel)
			}
			raw, err := json.Marshal(body)
			require.NoError(t, err)

			cr, err := decodeCompletionsRequest(raw)
			require.NoError(t, err, "an invalid option must not fail the request")
			assert.Equal(t, tt.wantSeed, cr.Seed)
			assert.Equal(t, tt.wantPar, cr.ParallelToolCalls)
			require.Len(t, cr.Messages, 1)
		})
	}
}

func TestMistralEncodeRequest_RandomSeed(t *testing.T) {
	t.Parallel()

	seed := int64(7)
	req := &CanonicalRequest{Model: "mistral-large-latest", Seed: &seed, Messages: []CanonicalMessage{{Role: "user", Content: "hi"}}}
	out, err := (&MistralAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &fields))
	assert.JSONEq(t, `7`, string(fields["random_seed"]))
	assert.NotContains(t, fields, "seed")
	assert.Equal(t, &seed, req.Seed, "the canonical request keeps its seed")

	out, err = (&MistralAdapter{}).EncodeRequest(&CanonicalRequest{Model: "m", Messages: []CanonicalMessage{{Role: "user", Content: "hi"}}})
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(out, &fields))
	assert.NotContains(t, fields, "random_seed")
}

func TestJSONSchemaFormatCrossesChatAndResponses(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()

	responses := `{"model":"m","input":"hi","text":{"format":{"type":"json_schema","name":"answer","strict":true,"schema":{"type":"object"}}}}`
	out, err := reg.AdaptRequest([]byte(responses), FormatOpenAIResponses, FormatMistral)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &fields))
	assert.JSONEq(t, `{"type":"json_schema","json_schema":{"name":"answer","strict":true,"schema":{"type":"object"}}}`, string(fields["response_format"]))

	schemaless := `{"model":"m","input":"hi","text":{"format":{"type":"json_schema"}}}`
	out, err = reg.AdaptRequest([]byte(schemaless), FormatOpenAIResponses, FormatMistral)
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(out, &fields))
	assert.NotContains(t, fields, "response_format", "a json_schema format without its schema is never sent")

	chat := `{"model":"m","response_format":{"type":"json_schema"},"messages":[{"role":"user","content":"hi"}]}`
	out, err = reg.AdaptRequest([]byte(chat), FormatOpenAI, FormatOpenAIResponses)
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(out, &fields))
	assert.NotContains(t, fields, "text")
}
