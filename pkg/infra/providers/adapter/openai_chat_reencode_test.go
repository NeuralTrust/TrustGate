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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The golden bodies under testdata/openai_chat_reencode/{groq,openrouter} are
// what the gateway sent before ENG-1618 S3; chatReencodeAdditions lists the
// keys each fixture is expected to gain since.
var chatReencodeAdditions = map[string]map[Format]string{
	"02_openai_python_kitchen.json": {
		FormatGroq:       `{"seed":42}`,
		FormatOpenRouter: `{"seed":42,"user":"user-123"}`,
	},
	"03_langchain_stream_tools.json": {
		FormatOpenRouter: `{"parallel_tool_calls":false}`,
	},
	"12_openrouter_extras.json": {
		FormatOpenRouter: `{"provider":{"order":["anthropic"]},"session_id":"s1","user":"u"}`,
	},
}

func TestAdaptRequest_OpenAIChatReEncodesForGroqAndOpenRouter(t *testing.T) {
	t.Parallel()

	dir := filepath.Join("testdata", "openai_chat_reencode")
	requests, err := filepath.Glob(filepath.Join(dir, "request", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, requests)

	reg := NewRegistry()
	for _, target := range []struct {
		format   Format
		provider string
	}{{FormatGroq, provider.Groq}, {FormatOpenRouter, provider.OpenRouter}} {
		for _, path := range requests {
			name := filepath.Base(path)
			t.Run(string(target.format)+"/"+strings.TrimSuffix(name, ".json"), func(t *testing.T) {
				t.Parallel()
				body, err := os.ReadFile(path)
				require.NoError(t, err)
				golden, err := os.ReadFile(filepath.Join(dir, string(target.format), name))
				require.NoError(t, err)

				out, err := reg.AdaptRequestForProvider(body, FormatOpenAI, target.format, target.provider, "")
				require.NoError(t, err)
				out = NormalizeRequestForProvider(target.provider, target.format, out)

				assert.JSONEq(t, withJSONKeys(t, golden, chatReencodeAdditions[name][target.format]), string(out))
			})
		}
	}
}

func withJSONKeys(t *testing.T, base []byte, extra string) string {
	t.Helper()
	if extra == "" {
		return string(base)
	}
	var fields, add map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(base, &fields))
	require.NoError(t, json.Unmarshal([]byte(extra), &add))
	for k, v := range add {
		fields[k] = v
	}
	out, err := json.Marshal(fields)
	require.NoError(t, err)
	return string(out)
}

func TestAdaptRequest_OpenRouterGraftsOnlyAllowlistedClientKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "routing and cache keys are kept, model and billing overrides are not",
			body: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"order":["Anthropic"],"allow_fallbacks":false},` +
				`"session_id":"s-1","user":"u-1","models":["a","b"],"plugins":[{"id":"web"}],"route":"fallback","transforms":["middle-out"],` +
				`"usage":{"include":true},"reasoning":{"effort":"low"}}`,
			want: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"order":["Anthropic"],"allow_fallbacks":false},"session_id":"s-1","user":"u-1"}`,
		},
		{
			name: "model keys inside provider are dropped",
			body: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"order":["Anthropic"],"model":"x","models":["y"]}}`,
			want: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":{"order":["Anthropic"]}}`,
		},
		{
			name: "keys of the wrong type are dropped",
			body: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":"Anthropic","session_id":7,"user":{"id":"u"}}`,
			want: `{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			name: "null keys are dropped",
			body: `{"model":"m","messages":[{"role":"user","content":"hi"}],"provider":null,"session_id":null}`,
			want: `{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
		},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := reg.AdaptRequestForProvider([]byte(tt.body), FormatOpenAI, FormatOpenRouter, provider.OpenRouter, "")
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(out))
		})
	}
}

func TestAdaptRequest_OpenRouterGraftSkipsNonChatSources(t *testing.T) {
	t.Parallel()

	body := `{"model":"anthropic/claude-sonnet-4.5","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"provider":{"order":["Anthropic"]},"session_id":"s-1"}`
	out, err := NewRegistry().AdaptRequestForProvider([]byte(body), FormatAnthropic, FormatOpenRouter, provider.OpenRouter, "")
	require.NoError(t, err)
	assert.NotContains(t, string(out), "provider")
	assert.NotContains(t, string(out), "session_id")
}

func TestAdaptRequest_OpenAIChatMarkersReachOpenRouterParts(t *testing.T) {
	t.Parallel()

	part := func(text, ttl string) string {
		switch ttl {
		case "-":
			return `"` + text + `"`
		case "":
			return `[{"type":"text","text":"` + text + `","cache_control":{"type":"ephemeral"}}]`
		default:
			return `[{"type":"text","text":"` + text + `","cache_control":{"type":"ephemeral","ttl":"` + ttl + `"}}]`
		}
	}
	request := func(model string, system string, ttls ...string) string {
		msgs := []string{`{"role":"developer","content":` + part("sys", system) + `}`}
		for i, ttl := range ttls {
			msgs = append(msgs, `{"role":"user","content":`+part("m"+string(rune('1'+i)), ttl)+`}`)
		}
		return `{"model":"` + model + `","cache_control":{"type":"ephemeral"},"session_id":"s-1","messages":[` + strings.Join(msgs, ",") + `]}`
	}
	want := func(model string, auto bool, system string, ttls ...string) string {
		msgs := []string{`{"role":"system","content":` + part("sys", system) + `}`}
		for i, ttl := range ttls {
			msgs = append(msgs, `{"role":"user","content":`+part("m"+string(rune('1'+i)), ttl)+`}`)
		}
		top := ""
		if auto {
			top = `"cache_control":{"type":"ephemeral"},`
		}
		return `{"model":"` + model + `",` + top + `"session_id":"s-1","messages":[` + strings.Join(msgs, ",") + `]}`
	}

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "anthropic lowers a 1h marker after a 5m one and keeps top-level auto",
			body: request("anthropic/claude-sonnet-4.5", "1h", "", "1h"),
			want: want("anthropic/claude-sonnet-4.5", true, "1h", "", "5m"),
		},
		{
			name: "anthropic caps at four breakpoints dropping the earliest messages",
			body: request("anthropic/claude-sonnet-4.5", "1h", "1h", "", "1h", "1h"),
			want: want("anthropic/claude-sonnet-4.5", true, "1h", "-", "-", "1h", "1h"),
		},
		{
			name: "gemini takes 5m breakpoints and no top-level auto",
			body: request("google/gemini-2.5-pro", "1h", ""),
			want: want("google/gemini-2.5-pro", false, "5m", ""),
		},
		{
			name: "a model OpenRouter caches implicitly gets no markers",
			body: request("meta-llama/llama-3.3-70b-instruct", "1h", ""),
			want: want("meta-llama/llama-3.3-70b-instruct", false, "-", "-"),
		},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := reg.AdaptRequestForProvider([]byte(tt.body), FormatOpenAI, FormatOpenRouter, provider.OpenRouter, "")
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(out))
		})
	}
}

func TestAdaptRequest_OpenAIChatKeepsSeedSchemaAndParallelToolCalls(t *testing.T) {
	t.Parallel()

	const schema = `{"name":"answer","strict":true,"schema":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"],"additionalProperties":false}}`
	body := `{"model":"m","seed":42,"parallel_tool_calls":true,"response_format":{"type":"json_schema","json_schema":` + schema + `},` +
		`"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"hi"}]}`

	reg := NewRegistry()
	for _, target := range []struct {
		format   Format
		parallel string
	}{{FormatGroq, `false`}, {FormatOpenRouter, `true`}} {
		out, err := reg.AdaptRequestForProvider([]byte(body), FormatOpenAI, target.format, string(target.format), "")
		require.NoError(t, err)
		out = NormalizeRequestForProvider(string(target.format), target.format, out)
		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out, &got))
		assert.JSONEq(t, `42`, string(got["seed"]), "%s", target.format)
		assert.JSONEq(t, target.parallel, string(got["parallel_tool_calls"]), "%s", target.format)
		assert.JSONEq(t, `{"type":"json_schema","json_schema":`+schema+`}`, string(got["response_format"]), "%s", target.format)
	}

	out, err := reg.AdaptRequestForProvider([]byte(`{"model":"m","parallel_tool_calls":false,"messages":[{"role":"user","content":"hi"}]}`), FormatOpenAI, FormatOpenRouter, provider.OpenRouter, "")
	require.NoError(t, err)
	assert.NotContains(t, string(out), "parallel_tool_calls", "OpenAI rejects parallel_tool_calls without tools")
}
