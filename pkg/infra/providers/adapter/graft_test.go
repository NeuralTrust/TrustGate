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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const graftEmail = "alice@example.com"

func graftEdit(t *testing.T, format Format, body string, edit func(*CanonicalRequest)) (string, *CanonicalRequest) {
	t.Helper()
	ad, err := NewRegistry().GetAdapter(format)
	require.NoError(t, err)
	req, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	baseline := req.Clone()
	edit(req)
	out, err := GraftChangedFields(ad, []byte(body), baseline, req)
	require.NoError(t, err)
	require.True(t, json.Valid(out), string(out))
	return string(out), req
}

func maskEmail(req *CanonicalRequest) {
	req.System = strings.ReplaceAll(req.System, graftEmail, "[EMAIL]")
	for i := range req.Messages {
		req.Messages[i].Content = strings.ReplaceAll(req.Messages[i].Content, graftEmail, "[EMAIL]")
	}
}

var graftBodies = []struct {
	name   string
	format Format
	body   string
}{
	{
		name:   "anthropic keeps system markers and other blocks",
		format: FormatAnthropic,
		body: `{"model":"claude-sonnet-4-5","max_tokens":64,
  "system":[{"type":"text","text":"You are terse.","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"text","text":"Volatile"}],
  "messages":[
    {"role":"user","content":[{"type":"text","text":"Stable context\nline two","cache_control":{"type":"ephemeral"}},{"type":"text","text":"mail me at ` + graftEmail + `"}]},
    {"role":"assistant","content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t1","name":"lookup","input":{"q":"x"}}]},
    {"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"found"},{"type":"text","text":"again ` + graftEmail + `","cache_control":{"type":"ephemeral"}}]}
  ],
  "thinking":{"type":"enabled","budget_tokens":1024},
  "tools":[{"name":"lookup","input_schema":{"type":"object","properties":{"q":{"type":"string"}}},"cache_control":{"type":"ephemeral"}}]}`,
	},
	{
		name:   "openai chat keeps system messages and part markers",
		format: FormatOpenAI,
		body: `{"model":"gpt-4o","messages":[
  {"role":"system","content":"Rules"},
  {"role":"developer","content":[{"type":"text","text":"Dev notes","cache_control":{"type":"ephemeral"}}]},
  {"role":"user","content":[{"type":"text","text":"Prefix"},{"type":"text","text":"reach ` + graftEmail + ` today"}]}
 ],"logprobs":true,"n":1,"prompt_cache_key":"k1",
 "tools":[{"type":"function","function":{"name":"f","strict":true,"parameters":{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"string"}}}}}]}`,
	},
	{
		name:   "responses codex body keeps unmodelled fields",
		format: FormatOpenAIResponses,
		body: `{"model":"gpt-5.6","instructions":"You are Codex.","input":[
  {"type":"message","role":"developer","content":[{"type":"input_text","text":"<permissions>ro</permissions>"}]},
  {"type":"message","role":"user","content":[{"type":"input_text","text":"<env>cwd</env>"},{"type":"input_text","text":"email ` + graftEmail + `","prompt_cache_breakpoint":{"mode":"explicit"}}]},
  {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAA"},
  {"type":"function_call","call_id":"c1","name":"shell","arguments":"{\"cmd\":\"ls\"}"},
  {"type":"function_call_output","call_id":"c1","output":"file.txt"}
 ],
 "tools":[{"type":"function","name":"shell","strict":false,"parameters":{"type":"object","properties":{"cmd":{"type":"string"}}}}],
 "tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"high","summary":"auto"},
 "store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":"sess-1","stream":true}`,
	},
	{
		name:   "bedrock converse keeps cachePoints",
		format: FormatBedrock,
		body: `{"modelId":"anthropic.claude-sonnet-4-5","system":[{"text":"Sys"},{"cachePoint":{"type":"default"}}],
 "messages":[{"role":"user","content":[{"text":"Stable"},{"cachePoint":{"type":"default"}},{"text":"hi ` + graftEmail + `"}]}],
 "inferenceConfig":{"maxTokens":64}}`,
	},
	{
		name:   "gemini keeps parts",
		format: FormatGemini,
		body:   `{"systemInstruction":{"parts":[{"text":"Sys"}]},"contents":[{"role":"user","parts":[{"text":"a"},{"text":"to ` + graftEmail + `"}]}],"generationConfig":{"maxOutputTokens":8}}`,
	},
	{
		name:   "cohere keeps messages",
		format: FormatCohere,
		body:   `{"model":"command-a","messages":[{"role":"system","content":"Sys"},{"role":"user","content":"to ` + graftEmail + `"}],"safety_mode":"OFF"}`,
	},
}

func TestGraftChangedFieldsMasksOnlyTheChangedText(t *testing.T) {
	t.Parallel()
	cases := graftBodies
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, _ := graftEdit(t, tc.format, tc.body, maskEmail)
			assert.Equal(t, strings.ReplaceAll(tc.body, graftEmail, "[EMAIL]"), out)
		})
	}
}

func TestGraftChangedFieldsReturnsOriginalWhenNothingChanged(t *testing.T) {
	t.Parallel()
	body := `{ "model" : "claude",  "max_tokens":8, "messages":[{"role":"user","content":"hi"}], "zzz": 1 }`
	out, _ := graftEdit(t, FormatAnthropic, body, func(*CanonicalRequest) {})
	assert.Equal(t, body, out)
}

func TestGraftChangedFieldsMapsTextOntoBlocksByNewlines(t *testing.T) {
	t.Parallel()
	body := `{"model":"claude","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"one\ntwo","cache_control":{"type":"ephemeral"}},{"type":"text","text":"three"}]}]}`
	out, _ := graftEdit(t, FormatAnthropic, body, func(r *CanonicalRequest) {
		r.Messages[0].Content = "ONE\ntwo\nTHREE"
	})
	assert.Equal(t, `{"model":"claude","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"ONE\ntwo","cache_control":{"type":"ephemeral"}},{"type":"text","text":"THREE"}]}]}`, out)
}

func TestGraftChangedFieldsReencodesOnlyTheMessageWhoseLinesChanged(t *testing.T) {
	t.Parallel()
	first := `{"role":"user","content":[{"type":"text","text":"keep","cache_control":{"type":"ephemeral"}},{"type":"text","text":"me"}]}`
	body := `{"model":"claude","max_tokens":8,"messages":[` + first + `,{"role":"assistant","content":"ok"},{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}],"extra":{"x":1}}`
	out, req := graftEdit(t, FormatAnthropic, body, func(r *CanonicalRequest) {
		r.Messages[2].Content = "a b"
	})
	assert.True(t, strings.HasPrefix(out, `{"model":"claude","max_tokens":8,"messages":[`+first+`,{"role":"assistant","content":"ok"},{"role":"user","content":`), out)
	assert.True(t, strings.HasSuffix(out, `}],"extra":{"x":1}}`), out)
	decoded, err := NewRegistry().DecodeRequestFor([]byte(out), FormatAnthropic)
	require.NoError(t, err)
	assert.Equal(t, req.Messages[2].Content, decoded.Messages[2].Content)
}

func TestGraftChangedFieldsFallsBackWhenMessagesChange(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"logprobs":true}`
	out, req := graftEdit(t, FormatOpenAI, body, func(r *CanonicalRequest) {
		r.Messages = append(r.Messages, CanonicalMessage{Role: "user", Content: "more"})
	})
	encoded, err := encodeCompletionsRequest(req)
	require.NoError(t, err)
	assert.Equal(t, string(encoded), out)
}

func TestGraftChangedFieldsFilterTools(t *testing.T) {
	t.Parallel()
	anthropic := func(tools string) string {
		return `{"model":"claude","max_tokens":8,"tools":[` + tools + `],"messages":[{"role":"user","content":"hi"}]}`
	}
	toolA := `{"name":"a","input_schema":{"type":"object","z":1,"a":2}}`
	toolB := `{"name":"b","input_schema":{"type":"object"}}`
	toolC := `{"name":"c","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"1h"}}`
	keep := func(names ...string) func(*CanonicalRequest) {
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

	t.Run("unmarked tool removed", func(t *testing.T) {
		t.Parallel()
		out, _ := graftEdit(t, FormatAnthropic, anthropic(toolA+","+toolB+","+toolC), keep("a", "c"))
		assert.Equal(t, anthropic(toolA+","+toolC), out)
	})
	t.Run("marked tool removed moves its marker", func(t *testing.T) {
		t.Parallel()
		out, _ := graftEdit(t, FormatAnthropic, anthropic(toolA+","+toolB+","+toolC), keep("a", "b"))
		assert.True(t, strings.HasPrefix(out, `{"model":"claude","max_tokens":8,"tools":[`+toolA+`,`), out)
		decoded, err := NewRegistry().DecodeRequestFor([]byte(out), FormatAnthropic)
		require.NoError(t, err)
		require.Len(t, decoded.Tools, 2)
		assert.Nil(t, decoded.Tools[0].Cache)
		require.NotNil(t, decoded.Tools[1].Cache)
		assert.Equal(t, CacheTTL1h, decoded.Tools[1].Cache.TTL)
	})
	t.Run("chat keeps strict and unmodelled keys", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"a","strict":true,"parameters":{"type":"object"}}},{"type":"function","function":{"name":"b"}}],"tool_choice":"required","n":1}`
		out, _ := graftEdit(t, FormatOpenAI, body, keep("a"))
		assert.Equal(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"a","strict":true,"parameters":{"type":"object"}}}],"tool_choice":"required","n":1}`, out)
	})
	t.Run("chat drops parallel_tool_calls with the last tool", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"b"}}],"parallel_tool_calls":false,"n":1}`
		out, _ := graftEdit(t, FormatOpenAI, body, keep())
		assert.Equal(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"n":1}`, out)
	})
	t.Run("responses drops built-in tools it cannot see", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"a","strict":true},{"type":"function","name":"b"}],"store":false}`
		out, _ := graftEdit(t, FormatOpenAIResponses, body, keep("b"))
		assert.Equal(t, `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"b"}],"store":false}`, out)
	})
	t.Run("bedrock cachePoint follows its tool", func(t *testing.T) {
		t.Parallel()
		spec := func(n string) string {
			return `{"toolSpec":{"name":"` + n + `","inputSchema":{"json":{"type":"object"}}}}`
		}
		cp := `{"cachePoint":{"type":"default"}}`
		body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` + spec("a") + `,` + cp + `,` + spec("b") + `,` + spec("c") + `]}}`
		out, _ := graftEdit(t, FormatBedrock, body, keep("a", "c"))
		assert.Equal(t, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[`+spec("a")+`,`+cp+`,`+spec("c")+`]}}`, out)
	})
	t.Run("all tools removed drops the key", func(t *testing.T) {
		t.Parallel()
		out, _ := graftEdit(t, FormatAnthropic, anthropic(toolB), keep())
		assert.Equal(t, `{"model":"claude","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`, out)
	})
}

func TestGraftChangedFieldsInjectsTools(t *testing.T) {
	t.Parallel()
	body := `{"model":"claude","max_tokens":8,"tools":[{"name":"a","input_schema":{"type":"object","z":1,"a":2},"cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`
	out, _ := graftEdit(t, FormatAnthropic, body, func(r *CanonicalRequest) {
		r.Tools = append(r.Tools, CanonicalTool{Name: "x", Schema: map[string]interface{}{"type": "object"}})
	})
	assert.Equal(t, `{"model":"claude","max_tokens":8,"tools":[{"name":"a","input_schema":{"type":"object","z":1,"a":2},"cache_control":{"type":"ephemeral"}},{"name":"x","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`, out)

	body = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	out, _ = graftEdit(t, FormatOpenAI, body, func(r *CanonicalRequest) {
		r.Tools = append(r.Tools, CanonicalTool{Name: "x"})
	})
	assert.Equal(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x"}}]}`, out)
}

func TestFilterTools(t *testing.T) {
	t.Parallel()
	tools := []CanonicalTool{{Name: "a"}, {Name: "b", Cache: bp(CacheTTL5m)}, {Name: "c", Cache: bp(CacheTTL1h)}}
	byName := func(names ...string) func(CanonicalTool) bool {
		return func(t CanonicalTool) bool {
			for _, n := range names {
				if t.Name == n {
					return true
				}
			}
			return false
		}
	}
	kept := FilterTools(tools, byName("a", "c"))
	require.Len(t, kept, 2)
	assert.Equal(t, bp(CacheTTL5m), kept[0].Cache)
	assert.Equal(t, bp(CacheTTL1h), kept[1].Cache)

	kept = FilterTools(tools, byName("a", "b"))
	require.Len(t, kept, 2)
	assert.Equal(t, bp(CacheTTL1h), kept[1].Cache)
	assert.Equal(t, bp(CacheTTL5m), tools[1].Cache)

	kept = FilterTools(tools, byName("c"))
	require.Len(t, kept, 1)
	assert.Equal(t, bp(CacheTTL1h), kept[0].Cache)
}

func TestCloneSharesNothingPluginsEdit(t *testing.T) {
	t.Parallel()
	req := &CanonicalRequest{
		System:   "s",
		Messages: []CanonicalMessage{{Role: "user", Content: "a", ToolCalls: []CanonicalToolCall{{Name: "f"}}, Cache: bp(CacheTTL5m)}},
		Tools:    []CanonicalTool{{Name: "t", Cache: bp(CacheTTL1h)}},
	}
	c := req.Clone()
	c.Messages[0].Content = "b"
	c.Messages[0].ToolCalls[0].Arguments = "{}"
	c.Messages[0].Cache.TTL = CacheTTL1h
	c.Tools[0].Name = "u"
	assert.Equal(t, "a", req.Messages[0].Content)
	assert.Empty(t, req.Messages[0].ToolCalls[0].Arguments)
	assert.Equal(t, CacheTTL5m, req.Messages[0].Cache.TTL)
	assert.Equal(t, "t", req.Tools[0].Name)
}

func TestRawListEdits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		drop    []bool
		replace map[int][]byte
		added   [][]byte
		want    string
	}{
		{name: "first", drop: []bool{true, false, false}, want: "[ 2 ,\n 3 ]"},
		{name: "middle", drop: []bool{false, true, false}, want: "[ 1 , 3 ]"},
		{name: "last two", drop: []bool{false, true, true}, want: "[ 1 ]"},
		{name: "all", drop: []bool{true, true, true}, want: "[  ]"},
		{name: "replace and append after dropped tail", drop: []bool{false, false, true}, replace: map[int][]byte{0: []byte("9")}, added: [][]byte{[]byte("4")}, want: "[ 9 , 2,4 ]"},
		{name: "append to emptied", drop: []bool{true, true, true}, added: [][]byte{[]byte("4"), []byte("5")}, want: "[  4,5]"},
	}
	body := []byte("[ 1 , 2 ,\n 3 ]")
	items, err := rawItems(body, rawSpan{0, len(body)})
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := applyRawPatches(body, rawListEdits(items, len(body)-1, tc.drop, tc.replace, tc.added))
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(out))
		})
	}
}

func TestGraftChangedFieldsKeepsEveryEditItAccepts(t *testing.T) {
	t.Parallel()
	edits := map[string]func(*CanonicalRequest){
		"upper": func(r *CanonicalRequest) {
			r.System = strings.ToUpper(r.System)
			for i := range r.Messages {
				r.Messages[i].Content = strings.ToUpper(r.Messages[i].Content)
			}
		},
		"extra lines": func(r *CanonicalRequest) {
			r.System += "\nmore"
			for i := range r.Messages {
				r.Messages[i].Content += "\nmore"
			}
		},
		"drop tools": func(r *CanonicalRequest) { r.Tools = nil },
	}
	for _, tc := range graftBodies {
		for name, edit := range edits {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				out, req := graftEdit(t, tc.format, tc.body, edit)
				ad, err := NewRegistry().GetAdapter(tc.format)
				require.NoError(t, err)
				decoded, err := ad.DecodeRequest([]byte(out))
				require.NoError(t, err)
				encoded, err := ad.EncodeRequest(req)
				require.NoError(t, err)
				reencoded, err := ad.DecodeRequest(encoded)
				require.NoError(t, err)
				got := string(canonicalJSON(decoded))
				if got != string(canonicalJSON(req)) {
					assert.Equal(t, string(canonicalJSON(reencoded)), got)
				}
			})
		}
	}
}
