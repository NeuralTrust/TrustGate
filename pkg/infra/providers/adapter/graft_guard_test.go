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
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const leakSecret = "bob@corp.example"

// leakBodies carry the secret in the text a masking plugin edits and again
// in a field the canonical request does not model. A graft would keep that
// copy, which is why redaction plugins encode the request in full.
var leakBodies = []struct {
	name   string
	format Format
	body   string
}{
	{"chat prediction", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"reach S"}],"prediction":{"type":"content","content":"reach S"}}`},
	{"chat message name", FormatOpenAI, `{"model":"m","messages":[{"role":"user","name":"S","content":"reach S"}]}`},
	{"chat metadata", FormatOpenAI, `{"model":"m","store":true,"metadata":{"who":"S"},"messages":[{"role":"user","content":"reach S"}]}`},
	{"chat user", FormatOpenAI, `{"model":"m","user":"S","messages":[{"role":"user","content":"reach S"}]}`},
	{"chat refusal", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":null,"refusal":"no S"},{"role":"user","content":"x"}]}`},
	{"chat refusal part", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":[{"type":"refusal","refusal":"no S"}]},{"role":"user","content":"x"}]}`},
	{"chat file part", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"reach S"},{"type":"file","file":{"filename":"S.txt","file_data":"data:,x"}}]}]}`},
	{"chat input_audio part", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"reach S"},{"type":"input_audio","input_audio":{"data":"S","format":"wav"}}]}]}`},
	{"chat functions", FormatOpenAI, `{"model":"m","functions":[{"name":"f","description":"S"}],"messages":[{"role":"user","content":"reach S"}]}`},
	{"chat web_search_options", FormatOpenAI, `{"model":"m","web_search_options":{"user_location":{"type":"approximate","approximate":{"city":"S"}}},"messages":[{"role":"user","content":"reach S"}]}`},
	{"chat text part with content", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"reach S","content":"reach S"}]}]}`},
	{"chat escaped copy", FormatOpenAI, `{"model":"m","metadata":{"who":"bob\u0040corp.example"},"messages":[{"role":"user","content":"reach S"}]}`},
	{"chat copy as key", FormatOpenAI, `{"model":"m","metadata":{"S":"x"},"messages":[{"role":"user","content":"reach S"}]}`},
	{"responses reasoning summary", FormatOpenAIResponses, `{"model":"m","input":[{"role":"user","content":"reach S"},{"type":"reasoning","id":"rs","summary":[{"type":"summary_text","text":"about S"}]},{"role":"user","content":"ok"}]}`},
	{"responses prompt variables", FormatOpenAIResponses, `{"model":"m","prompt":{"id":"p","variables":{"x":"S"}},"input":"reach S"}`},
	{"responses custom_tool_call", FormatOpenAIResponses, `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"reach S"}]},{"type":"custom_tool_call","call_id":"c","name":"apply_patch","input":"*** S"},{"type":"custom_tool_call_output","call_id":"c","output":"done S"}]}`},
	{"responses local_shell_call_output", FormatOpenAIResponses, `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"reach S"}]},{"type":"local_shell_call_output","call_id":"c","output":"S"}]}`},
	{"responses mcp_call output", FormatOpenAIResponses, `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"reach S"}]},{"type":"mcp_call","id":"m","server_label":"s","name":"n","arguments":"{}","output":"S"}]}`},
	{"responses annotations", FormatOpenAIResponses, `{"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"reach S"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok","annotations":[{"type":"url_citation","title":"S","url":"u"}]}]},{"type":"message","role":"user","content":"again"}]}`},
	{"anthropic thinking", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":[{"type":"thinking","thinking":"reach S","signature":"s"},{"type":"text","text":"ok"}]},{"role":"user","content":"go"}]}`},
	{"anthropic redacted_thinking", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":[{"type":"redacted_thinking","data":"S"},{"type":"text","text":"ok"}]},{"role":"user","content":"go"}]}`},
	{"anthropic document text", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"doc S"},"title":"S"},{"type":"text","text":"reach S"}]}]}`},
	{"anthropic search_result", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":[{"type":"search_result","source":"s","title":"t","content":[{"type":"text","text":"sr S"}]},{"type":"text","text":"reach S"}]}]}`},
	{"anthropic web search result", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":[{"type":"server_tool_use","id":"s1","name":"web_search","input":{"query":"q"}},{"type":"web_search_tool_result","tool_use_id":"s1","content":[{"type":"web_search_result","title":"S","url":"u","encrypted_content":"e"}]},{"type":"text","text":"ok"}]},{"role":"user","content":"b"}]}`},
	{"anthropic citations", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"reach S"},{"role":"assistant","content":[{"type":"text","text":"ok","citations":[{"type":"char_location","cited_text":"S","document_index":0,"start_char_index":0,"end_char_index":1}]}]},{"role":"user","content":"b"}]}`},
	{"anthropic mcp_servers token", FormatAnthropic, `{"model":"m","max_tokens":5,"mcp_servers":[{"type":"url","url":"https://m","name":"m","authorization_token":"S"}],"messages":[{"role":"user","content":"reach S"}]}`},
	{"bedrock guardContent", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"reach S"},{"guardContent":{"text":{"text":"g S"}}}]}]}`},
	{"bedrock reasoningContent", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"reach S"}]},{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"think S","signature":"s"}}},{"text":"ok"}]},{"role":"user","content":[{"text":"go"}]}]}`},
	{"bedrock document source text", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"reach S"},{"document":{"format":"txt","name":"d","source":{"text":"doc S"}}}]}]}`},
	{"bedrock promptVariables", FormatBedrock, `{"promptVariables":{"v":{"text":"S"}},"messages":[{"role":"user","content":[{"text":"reach S"}]}]}`},
	{"gemini thought part", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"reach S"}]},{"role":"model","parts":[{"text":"think S","thought":true},{"text":"ok"}]},{"role":"user","parts":[{"text":"go"}]}]}`},
	{"gemini labels", FormatGemini, `{"labels":{"x":"S"},"contents":[{"role":"user","parts":[{"text":"reach S"}]}]}`},
	{"gemini inlineData", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"reach S"},{"inlineData":{"mimeType":"text/plain","data":"S"}}]}]}`},
	{"gemini executableCode", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"reach S"}]},{"role":"model","parts":[{"executableCode":{"language":"PYTHON","code":"print('S')"}},{"codeExecutionResult":{"outcome":"OUTCOME_OK","output":"S"}}]},{"role":"user","parts":[{"text":"b"}]}]}`},
	{"gemini snake system_instruction", FormatGemini, `{"system_instruction":{"parts":[{"text":"sys S"}]},"contents":[{"role":"user","parts":[{"text":"reach S"}]}]}`},
	{"cohere documents", FormatCohere, `{"model":"c","documents":[{"id":"d","data":{"text":"doc S","title":"S"}}],"messages":[{"role":"user","content":"reach S"}]}`},
	{"cohere document part", FormatCohere, `{"model":"c","messages":[{"role":"user","content":[{"type":"text","text":"reach S"},{"type":"document","document":{"data":{"text":"x S"}}}]}]}`},
}

func maskLeakSecret(req *CanonicalRequest) {
	req.System = strings.ReplaceAll(req.System, leakSecret, "[EMAIL]")
	for i := range req.Messages {
		req.Messages[i].Content = strings.ReplaceAll(req.Messages[i].Content, leakSecret, "[EMAIL]")
	}
}

func carriesDecoded(t *testing.T, body []byte, s string) bool {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(body, &v))
	var walk func(any) bool
	walk = func(v any) bool {
		switch v := v.(type) {
		case string:
			return strings.Contains(v, s)
		case []any:
			for _, e := range v {
				if walk(e) {
					return true
				}
			}
		case map[string]any:
			for k, e := range v {
				if strings.Contains(k, s) || walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

func graftWith(t *testing.T, format Format, body string, opts GraftOptions, edit func(*CanonicalRequest)) (out, encoded []byte) {
	t.Helper()
	ad, err := NewRegistry().GetAdapter(format)
	require.NoError(t, err)
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	baseline := req.Clone()
	edit(req)
	out, err = GraftChangedFieldsWith(ad, []byte(body), baseline, req, opts)
	require.NoError(t, err)
	encoded, err = ad.EncodeRequest(req)
	require.NoError(t, err)
	require.True(t, json.Valid(out), string(out))
	return out, encoded
}

func TestEncodeRequestDropsUnmodelledCopiesOfMaskedText(t *testing.T) {
	t.Parallel()
	for _, tc := range leakBodies {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := strings.ReplaceAll(tc.body, "S", leakSecret)
			_, encoded := graftWith(t, tc.format, body, GraftOptions{}, maskLeakSecret)
			assert.False(t, carriesDecoded(t, encoded, leakSecret), string(encoded))
		})
	}
}

func TestGraftChangedFieldsRefusesDuplicateKeys(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"top-level exact":     `{"model":"m","messages":[{"role":"user","content":"a ` + leakSecret + `"}],"messages":[{"role":"user","content":"hi ` + leakSecret + `"}]}`,
		"top-level case":      `{"model":"m","messages":[{"role":"user","content":"hi ` + leakSecret + `"}],"Messages":[{"role":"user","content":"decoy ` + leakSecret + `"}]}`,
		"nested exact":        `{"model":"m","messages":[{"role":"user","content":"a ` + leakSecret + `","content":"hi ` + leakSecret + `"}]}`,
		"nested case":         `{"model":"m","messages":[{"role":"user","content":"hi ` + leakSecret + `","CONTENT":"decoy ` + leakSecret + `"}]}`,
		"unicode fold":        `{"model":"m","messages":[{"role":"user","content":"hi ` + leakSecret + `"}],"metadata":{"ſ":"a","s":"b"}}`,
		"inside a tool entry": `{"model":"m","messages":[{"role":"user","content":"hi ` + leakSecret + `"}],"tools":[{"type":"function","function":{"name":"g","name":"f"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, encoded := graftWith(t, FormatOpenAI, body, GraftOptions{}, maskLeakSecret)
			assert.Equal(t, string(encoded), string(out))
		})
	}

	t.Run("unchanged body is normalised", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"m","messages":[{"role":"user","content":"a ` + leakSecret + `"}],"messages":[{"role":"user","content":"hello"}]}`
		out, encoded := graftWith(t, FormatOpenAI, body, GraftOptions{}, maskLeakSecret)
		assert.Equal(t, string(encoded), string(out))
	})
}

func TestRawFieldsRejectsKeysTheDecoderFolds(t *testing.T) {
	t.Parallel()
	for body, dup := range map[string]bool{
		`{"a":1,"b":2}`:             false,
		`{"a":1,"a":2}`:             true,
		`{"content":1,"Content":2}`: true,
		`{"system":1,"ſystem":2}`:   true,
		`{"k":1,"K":2}`:             true,
		`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"J":0,"j":1}`: true,
	} {
		_, err := rawFields([]byte(body), rawSpan{0, len(body)})
		if dup {
			assert.ErrorIs(t, err, errDuplicateKey, body)
		} else {
			assert.NoError(t, err, body)
		}
	}
}

func TestGraftChangedFieldsUnmodelledTools(t *testing.T) {
	t.Parallel()
	keepOnly := func(names ...string) func(*CanonicalRequest) {
		return func(r *CanonicalRequest) {
			r.Tools = FilterTools(r.Tools, func(t CanonicalTool) bool {
				for _, n := range names {
					if t.Name == n {
						return true
					}
				}
				return false
			})
		}
	}
	responses := `{"model":"m","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"a"},{"type":"mcp","server_label":"x","server_url":"https://x"},{"type":"function","name":"b"}]}`

	t.Run("dropped by default", func(t *testing.T) {
		t.Parallel()
		out, _ := graftWith(t, FormatOpenAIResponses, responses, GraftOptions{}, keepOnly("b"))
		assert.Equal(t, `{"model":"m","input":"hi","tools":[{"type":"function","name":"b"}]}`, string(out))
	})
	t.Run("kept by kind", func(t *testing.T) {
		t.Parallel()
		opts := GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool { return u.Kind == "web_search" }}
		out, _ := graftWith(t, FormatOpenAIResponses, responses, opts, keepOnly("b"))
		assert.Equal(t, `{"model":"m","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"b"}]}`, string(out))
	})
	t.Run("bedrock cache point after a dropped system tool stays with the tool before it", func(t *testing.T) {
		t.Parallel()
		spec := func(n string) string {
			return `{"toolSpec":{"name":"` + n + `","inputSchema":{"json":{"type":"object"}}}}`
		}
		cp := `{"cachePoint":{"type":"default"}}`
		body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` + cp + `,` + spec("a") + `,{"systemTool":{"name":"nova_grounding"}},` + cp + `,` + spec("b") + `]}}`
		out, _ := graftWith(t, FormatBedrock, body, GraftOptions{}, keepOnly("a"))
		assert.Equal(t, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[`+cp+`,`+spec("a")+`,`+cp+`]}}`, string(out))

		opts := GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool { return u.Kind == "systemTool:nova_grounding" }}
		out, _ = graftWith(t, FormatBedrock, body, opts, keepOnly("a"))
		assert.Equal(t, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[`+cp+`,`+spec("a")+`,{"systemTool":{"name":"nova_grounding"}},`+cp+`]}}`, string(out))
	})
	t.Run("gemini groups are replaced whole", func(t *testing.T) {
		t.Parallel()
		body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"},{"name":"b"}]},{"googleSearch":{}}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"generationConfig":{"maxOutputTokens":8}}`
		out, _ := graftWith(t, FormatGemini, body, GraftOptions{KeepUnmodelledTool: func(UnmodelledTool) bool { return true }}, keepOnly("a"))
		assert.Equal(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}]},{"googleSearch":{}}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"generationConfig":{"maxOutputTokens":8}}`, string(out))

		out, _ = graftWith(t, FormatGemini, body, GraftOptions{}, keepOnly("a"))
		assert.Equal(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}]}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"generationConfig":{"maxOutputTokens":8}}`, string(out))
	})
	t.Run("a refused kind goes though no modelled tool changed", func(t *testing.T) {
		t.Parallel()
		opts := GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool { return u.Kind == "web_search" }}
		out, _ := graftWith(t, FormatOpenAIResponses, responses, opts, func(*CanonicalRequest) {})
		assert.Equal(t, `{"model":"m","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"a"},{"type":"function","name":"b"}]}`, string(out))

		out, _ = graftWith(t, FormatOpenAIResponses, responses, GraftOptions{KeepUnmodelledTool: func(UnmodelledTool) bool { return true }}, func(*CanonicalRequest) {})
		assert.Equal(t, responses, string(out))
	})
	t.Run("only unmodelled tools left", func(t *testing.T) {
		t.Parallel()
		opts := GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool { return u.Kind == "web_search" }}
		out, _ := graftWith(t, FormatOpenAIResponses, responses, opts, keepOnly())
		assert.Equal(t, `{"model":"m","input":"hi","tools":[{"type":"web_search"}]}`, string(out))
	})
}

func TestUnmodelledTools(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		format Format
		body   string
		want   []string
	}{
		{"none", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"type":"function","name":"a"}]}`, nil},
		{"no tools", FormatOpenAIResponses, `{"model":"m","input":"hi"}`, nil},
		{"builtins", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"type":"mcp","server_label":"x"},{"type":"function","name":"a"},{"type":"local_shell"}]}`, []string{"mcp", "local_shell"}},
		{"a key the decoder folds", FormatOpenAIResponses, `{"model":"m","input":"hi","Tools":[{"type":"function","name":"a"},{"type":"mcp","server_label":"x"}]}`, []string{"mcp"}},
		{"a builtin named like a modelled tool", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"type":"function","name":"a"},{"type":"mcp","name":"a","server_label":"x"}]}`, []string{"function", "mcp"}},
		{"anthropic server tools are modelled by name", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"bash_20250124","name":"bash"}]}`, nil},
		{"gemini", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}]},{"googleSearch":{}},{"function_declarations":[{"name":"b"}]},{"functionDeclarations":[],"codeExecution":{}}]}`, []string{"googleSearch", "codeExecution"}},
		{"bedrock", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"a","inputSchema":{"json":{}}}},{"cachePoint":{"type":"default"}},{"systemTool":{"name":"nova_grounding"}}]}}`, []string{"systemTool:nova_grounding"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ad, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			req, err := ad.DecodeRequest([]byte(tc.body))
			require.NoError(t, err)
			got, ok := UnmodelledTools(ad, []byte(tc.body), req)
			require.True(t, ok)
			var kinds []string
			for _, u := range got {
				kinds = append(kinds, u.Kind)
			}
			assert.Equal(t, tc.want, kinds)
		})
	}
}

func TestGraftChangedFieldsPlacesEditsByOffset(t *testing.T) {
	t.Parallel()
	compress := func(r *CanonicalRequest) {
		r.Messages[0].Content = strings.Replace(r.Messages[0].Content, "x\n\n\n\ny", "x\n\ny", 1)
	}
	cases := []struct {
		name   string
		format Format
		body   string
		edit   func(*CanonicalRequest)
		want   string
	}{
		{
			name:   "bedrock block before a cache point loses lines",
			format: FormatBedrock,
			body:   `{"messages":[{"role":"user","content":[{"text":"x\n\n\n\ny"},{"cachePoint":{"type":"default"}},{"text":"p\nq\nr\ns"}]}]}`,
			edit:   compress,
			want:   `{"messages":[{"role":"user","content":[{"text":"x\n\ny"},{"cachePoint":{"type":"default"}},{"text":"p\nq\nr\ns"}]}]}`,
		},
		{
			name:   "anthropic marked block loses lines",
			format: FormatAnthropic,
			body:   `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"x\n\n\n\ny","cache_control":{"type":"ephemeral"}},{"type":"text","text":"p\nq\nr\ns"}]}]}`,
			edit:   compress,
			want:   `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"x\n\ny","cache_control":{"type":"ephemeral"}},{"type":"text","text":"p\nq\nr\ns"}]}]}`,
		},
		{
			name:   "anthropic marked block gains a line",
			format: FormatAnthropic,
			body:   `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"a\nb","cache_control":{"type":"ephemeral"}},{"type":"text","text":"c"}]}]}`,
			edit:   func(r *CanonicalRequest) { r.Messages[0].Content = "a\nX\nb\nc" },
			want:   `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"a\nX\nb","cache_control":{"type":"ephemeral"}},{"type":"text","text":"c"}]}]}`,
		},
		{
			name:   "two masks in two blocks keep the joiner",
			format: FormatBedrock,
			body:   `{"messages":[{"role":"user","content":[{"text":"x AAA"},{"cachePoint":{"type":"default"}},{"text":"BBB y"}]}]}`,
			edit:   func(r *CanonicalRequest) { r.Messages[0].Content = "x [X]\n[X] y" },
			want:   `{"messages":[{"role":"user","content":[{"text":"x [X]"},{"cachePoint":{"type":"default"}},{"text":"[X] y"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, _ := graftWith(t, tc.format, tc.body, GraftOptions{}, tc.edit)
			assert.Equal(t, tc.want, string(out))
		})
	}

	t.Run("an edit across a joiner re-encodes the message", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"keep","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":[{"type":"text","text":"card 4111"},{"type":"text","text":"1111 end"}]}]}`
		out, _ := graftWith(t, FormatAnthropic, body, GraftOptions{}, func(r *CanonicalRequest) {
			r.Messages[1].Content = "card [CARD] end"
		})
		assert.True(t, strings.HasPrefix(string(out), `{"model":"c","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"keep","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":`), string(out))
		assert.NotContains(t, string(out), "4111")
	})
}

func TestGraftChangedFieldsGeminiToolConfigIsNotBedrock(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"},{"name":"b"}]}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"generationConfig":{"maxOutputTokens":8}}`
	out, encoded := graftWith(t, FormatGemini, body, GraftOptions{}, func(r *CanonicalRequest) { r.Tools = r.Tools[:1] })
	assert.NotEqual(t, string(encoded), string(out))
	assert.Equal(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}]}],"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"generationConfig":{"maxOutputTokens":8}}`, string(out))
}

func TestGraftChangedFieldsSkipsBodiesOverTheValueCap(t *testing.T) {
	t.Parallel()
	extra := strings.TrimSuffix(strings.Repeat("0,", maxGraftValues), ",")
	body := `{"model":"m","messages":[{"role":"user","content":"hi ` + leakSecret + `"}],"metadata":{"n":[` + extra + `]}}`
	out, encoded := graftWith(t, FormatOpenAI, body, GraftOptions{}, maskLeakSecret)
	assert.Equal(t, string(encoded), string(out))
}

func TestDiffTextRebuildsTheEditedText(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(7))
	alphabet := []string{"a", "b", " ", "\n", "é", "bob", "@", "x.y", "日本"}
	word := func(n int) string {
		var sb strings.Builder
		for range n {
			sb.WriteString(alphabet[r.Intn(len(alphabet))])
		}
		return sb.String()
	}
	for range 2000 {
		before := word(r.Intn(30))
		after := before
		for range r.Intn(4) + 1 {
			x := r.Intn(len(after) + 1)
			y := x + r.Intn(len(after)-x+1)
			for x > 0 && !runeBoundary(after, x) {
				x--
			}
			for y < len(after) && !runeBoundary(after, y) {
				y++
			}
			after = after[:x] + word(r.Intn(3)) + after[y:]
		}
		hunks, ok := diffText(before, after)
		require.True(t, ok)
		var sb strings.Builder
		last := 0
		for _, h := range hunks {
			require.GreaterOrEqual(t, h.start, last)
			sb.WriteString(before[last:h.start])
			sb.WriteString(h.insert)
			last = h.end
		}
		sb.WriteString(before[last:])
		require.Equal(t, after, sb.String(), "before=%q", before)
	}

	hunks, ok := diffText("mail a@b.io and c@d.io now", "mail [EMAIL] and [EMAIL] now")
	require.True(t, ok)
	require.Len(t, hunks, 2)
	assert.Equal(t, textHunk{start: 5, end: 11, insert: "[EMAIL]"}, hunks[0])
	assert.Equal(t, textHunk{start: 16, end: 22, insert: "[EMAIL]"}, hunks[1])
}

// probeDriftBodies cover the text-bearing shapes each decoder reads.
var probeDriftBodies = []struct {
	format Format
	body   string
}{
	{FormatOpenAI, `{"model":"m","messages":[{"role":"system","content":"s"},{"role":"developer","content":[{"type":"text","text":"d"}]},{"role":"user","content":[{"type":"text","text":"u"},{"type":"image_url","image_url":{"url":"https://x"}},{"type":"input_text","text":"i"}]},{"role":"assistant","content":null,"refusal":"r","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c","content":[{"type":"text","text":"t"}]},{"role":"assistant","content":[{"type":"refusal","refusal":"rp"}]},{"role":"function","name":"f","content":"fn"}]}`},
	{FormatOpenAIResponses, `{"model":"m","instructions":"i","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"d"}]},{"role":"user","content":"u"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"o"},{"type":"refusal","refusal":"r"}]},{"type":"function_call","call_id":"c","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"c","output":"fo"},{"type":"custom_tool_call","call_id":"k","name":"p","input":"ci"},{"type":"custom_tool_call_output","call_id":"k","output":"co"},{"type":"reasoning","summary":[{"type":"summary_text","text":"rs"}]}]}`},
	{FormatOpenAIResponses, `{"model":"m","input":"plain"}`},
	{FormatAnthropic, `{"model":"m","max_tokens":5,"system":[{"type":"text","text":"s"}],"messages":[{"role":"system","content":"s2"},{"role":"user","content":[{"type":"text","text":"u"},{"type":"document","source":{"type":"text","data":"doc"}},{"type":"search_result","source":"s","title":"t","content":[{"type":"text","text":"sr"}]}]},{"role":"assistant","content":[{"type":"thinking","thinking":"th","signature":"s"},{"type":"text","text":"a"},{"type":"tool_use","id":"t","name":"f","input":{"text":"ti"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"text","text":"tr"}]}]},{"role":"user","content":"plain"}]}`},
	{FormatBedrock, `{"system":[{"text":"s"},{"guardContent":{"text":{"text":"g"}}}],"messages":[{"role":"user","content":[{"text":"u"},{"document":{"format":"txt","name":"d","source":{"text":"doc"}}}]},{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"r","signature":"s"}}},{"text":"a"},{"toolUse":{"toolUseId":"t","name":"f","input":{"text":"ti"}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"t","content":[{"text":"tr"},{"json":{"text":"j"}}]}}]}]}`},
	{FormatGemini, `{"systemInstruction":{"parts":[{"text":"s"}]},"contents":[{"role":"user","parts":[{"text":"u"},{"inlineData":{"mimeType":"text/plain","data":"x"}}]},{"role":"model","parts":[{"text":"th","thought":true},{"text":"a"},{"functionCall":{"name":"f","args":{"text":"ar"}}}]},{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"content":"fr"}}}]}]}`},
	{FormatCohere, `{"model":"c","documents":[{"id":"d","data":{"text":"doc"}}],"messages":[{"role":"system","content":"s"},{"role":"user","content":[{"type":"text","text":"u"},{"type":"document","document":{"data":{"text":"dp"}}}]},{"role":"assistant","tool_plan":"tp","tool_calls":[{"id":"c","type":"function","function":{"name":"f","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c","content":[{"type":"text","text":"t"}]}]}`},
	{FormatMistral, `{"model":"m","messages":[{"role":"system","content":"s"},{"role":"user","content":[{"type":"text","text":"u"}]},{"role":"assistant","content":"a"}]}`},
}

// TestProbeKeysCoverEveryDecodedTextKey fails when a decoder starts reading
// prompt text from a key probeKeys does not list: every string of the body
// is marked in turn, and a mark that reaches the system text or a message
// must sit under a probe key.
func TestProbeKeysCoverEveryDecodedTextKey(t *testing.T) {
	t.Parallel()
	const mark = "mark"
	for _, tc := range probeDriftBodies {
		t.Run(string(tc.format), func(t *testing.T) {
			t.Parallel()
			ad, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			body := []byte(tc.body)
			root, err := rawRoot(body)
			require.NoError(t, err)
			for _, leaf := range stringLeaves(t, body, root, "") {
				marked, err := applyRawPatches(body, []rawPatch{{at: leaf.span, with: marshalRawString(leaf.value + mark)}})
				require.NoError(t, err)
				req, err := ad.DecodeRequest(marked)
				if err != nil || req == nil {
					continue
				}
				text := req.System
				for _, m := range req.Messages {
					text += m.Content
				}
				if strings.Contains(text, mark) {
					assert.True(t, isProbeKey(leaf.key), "%s: text read from key %q (%q)", tc.format, leaf.key, leaf.value)
				}
			}
		})
	}
}

type stringLeaf struct {
	key, value string
	span       rawSpan
}

func stringLeaves(t *testing.T, b []byte, s rawSpan, key string) []stringLeaf {
	t.Helper()
	switch b[s.start] {
	case '"':
		v, ok := rawString(b, s)
		require.True(t, ok)
		return []stringLeaf{{key: key, value: v, span: s}}
	case '{':
		fields, err := rawFields(b, s)
		require.NoError(t, err)
		var out []stringLeaf
		for _, f := range fields {
			out = append(out, stringLeaves(t, b, f.value, f.key)...)
		}
		return out
	case '[':
		items, err := rawItems(b, s)
		require.NoError(t, err)
		var out []stringLeaf
		for _, it := range items {
			out = append(out, stringLeaves(t, b, it, "")...)
		}
		return out
	}
	return nil
}

func largeChatBody(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"model":"m","messages":[`)
	for i := range n {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"role":"user","content":[{"type":"text","text":"line a %d\nb"},{"type":"text","text":"mail %s x"}]}`, i, graftEmail)
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}

var largeBodyEdits = map[string]func(*CanonicalRequest){
	"mask every message": maskEmail,
	"rewrite every line": func(r *CanonicalRequest) {
		for i := range r.Messages {
			r.Messages[i].Content = "z"
		}
	},
}

// TestGraftChangedFieldsLargeBodyStaysLinear bounds the graft of an 8000
// message (about 1 MB) body by the decode and re-encode a plugin would run
// without it; a quadratic step shows up as a ratio in the hundreds.
func TestGraftChangedFieldsLargeBodyStaysLinear(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing test")
	}
	body := largeChatBody(8000)
	ad, err := NewRegistry().GetAdapter(FormatOpenAI)
	require.NoError(t, err)
	best := func(f func()) time.Duration {
		d := time.Duration(1 << 62)
		for range 3 {
			st := time.Now()
			f()
			d = min(d, time.Since(st))
		}
		return d
	}
	for name, edit := range largeBodyEdits {
		req, err := ad.DecodeRequest(body)
		require.NoError(t, err)
		baseline := req.Clone()
		edit(req)
		reencode := best(func() {
			_, _ = ad.DecodeRequest(body)
			_, _ = ad.EncodeRequest(req)
		})
		graft := best(func() {
			_, err := GraftChangedFields(ad, body, baseline, req)
			require.NoError(t, err)
		})
		t.Logf("%s: bytes=%d graft=%v decode+encode=%v", name, len(body), graft, reencode)
		assert.Less(t, graft, 5*reencode, name)
	}
}

func deepBody(depth int, inner string) []byte {
	x := strings.Repeat("[", depth) + inner + strings.Repeat("]", depth)
	return []byte(`{"model":"m","max_tokens":5,"x":` + x + `,"messages":[{"role":"user","content":"hi ` + leakSecret + `"}]}`)
}

// TestGraftChangedFieldsDeepBodiesStayLinear bounds bodies whose raw walk
// would rescan each value once per level above it: they fall back to the
// full re-encode after a linear pre-check.
func TestGraftChangedFieldsDeepBodiesStayLinear(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing test")
	}
	cases := map[string][]byte{
		"depth 4000 over a 6 MiB string": deepBody(4000, `"`+strings.Repeat("a", 6<<20)+`"`),
		"depth 60 over a 6 MiB string":   deepBody(60, `"`+strings.Repeat("a", 6<<20)+`"`),
		"depth 62 over 3M values":        deepBody(62, strings.TrimSuffix(strings.Repeat("0,", 3<<20), ",")),
	}
	ad, err := NewRegistry().GetAdapter(FormatAnthropic)
	require.NoError(t, err)
	best := func(f func()) time.Duration {
		d := time.Duration(1 << 62)
		for range 3 {
			st := time.Now()
			f()
			d = min(d, time.Since(st))
		}
		return d
	}
	for name, body := range cases {
		req, err := ad.DecodeRequest(body)
		require.NoError(t, err, name)
		baseline := req.Clone()
		maskLeakSecret(req)
		encoded, err := ad.EncodeRequest(req)
		require.NoError(t, err)
		reencode := best(func() {
			_, _ = ad.DecodeRequest(body)
			_, _ = ad.EncodeRequest(req)
		})
		var out []byte
		graft := best(func() {
			out, err = GraftChangedFields(ad, body, baseline, req)
			require.NoError(t, err)
		})
		t.Logf("%s: graft=%v decode+encode=%v", name, graft, reencode)
		assert.Equal(t, string(encoded), string(out), name)
		assert.Less(t, graft, 5*reencode, name)
	}
}

func TestRawWithinCaps(t *testing.T) {
	t.Parallel()
	assert.True(t, rawWithinCaps([]byte(`{"a":[{"b":"c\\\"]"}]}`)))
	assert.True(t, rawWithinCaps([]byte(strings.Repeat("[", maxGraftDepth)+strings.Repeat("]", maxGraftDepth))))
	assert.False(t, rawWithinCaps([]byte(strings.Repeat("[", maxGraftDepth+1)+strings.Repeat("]", maxGraftDepth+1))))
	assert.False(t, rawWithinCaps(deepBody(40, `"`+strings.Repeat("a", 1<<20)+`"`)))
	assert.False(t, rawWithinCaps([]byte("["+strings.TrimSuffix(strings.Repeat("0,", maxGraftValues+1), ",")+"]")))
}

func TestHasAmbiguousKeysReadsAnySizeAndDepth(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want bool
	}{
		"flat":              {`{"a":1,"b":{"a":2},"c":[{"a":3}]}`, false},
		"strings like keys": {`{"a":"b","c":["a","a"],"d":{"x":"a","y":"a"}}`, false},
		"escaped key":       {`{"a\u0062":1,"ab":2}`, true},
		"fold":              {`{"k":1,"K":2}`, true},
		"after a nested":    {`{"a":{"b":1,"c":2},"A":3}`, true},
		"many keys":         {`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"ſ":0,"s":1}`, true},
		"deep":              {strings.Repeat(`{"x":`, 5000) + `{"a":1,"a":2}` + strings.Repeat("}", 5000), true},
		"invalid":           {`{"a":1,"a":2`, false},
	} {
		assert.Equal(t, tc.want, HasAmbiguousKeys([]byte(tc.body)), name)
	}
}

func TestGraftChangedFieldsNormalisesUnchangedBodiesOverTheSizeCap(t *testing.T) {
	t.Parallel()
	pad := strings.Repeat("a", maxGraftBody)
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{"pad":"` + pad + `"},"messages":[{"role":"user","content":"decoy"}]}`
	out, encoded := graftWith(t, FormatOpenAI, body, GraftOptions{}, func(*CanonicalRequest) {})
	assert.Equal(t, string(encoded), string(out))

	body = `{"model":"m","messages":[{"role":"user","content":"hi"}],"metadata":{"pad":"` + pad + `"}}`
	out, _ = graftWith(t, FormatOpenAI, body, GraftOptions{}, func(*CanonicalRequest) {})
	assert.Equal(t, body, string(out))
}

func BenchmarkGraftChangedFields(b *testing.B) {
	body := largeChatBody(8000)
	ad, err := NewRegistry().GetAdapter(FormatOpenAI)
	require.NoError(b, err)
	for name, edit := range largeBodyEdits {
		req, err := ad.DecodeRequest(body)
		require.NoError(b, err)
		baseline := req.Clone()
		edit(req)
		b.Run(name+"/graft", func(b *testing.B) {
			for range b.N {
				_, _ = GraftChangedFields(ad, body, baseline, req)
			}
		})
		b.Run(name+"/encode", func(b *testing.B) {
			for range b.N {
				_, _ = ad.EncodeRequest(req)
			}
		})
		b.Run(name+"/decode", func(b *testing.B) {
			for range b.N {
				_, _ = ad.DecodeRequest(body)
			}
		})
	}
}
