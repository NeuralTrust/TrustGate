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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmodelledToolsRefusesRepeatedKeys(t *testing.T) {
	t.Parallel()
	const mcp = `{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"}`
	cases := []struct {
		name   string
		format Format
		body   string
	}{
		{"a repeated model", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[` + mcp + `],"model":"m"}`},
		{"a case variant of tools", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[` + mcp + `],"Tools":[]}`},
		{"bedrock toolConfig and toolconfig", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"systemTool":{"name":"nova_grounding"}}]},"toolconfig":null}`},
		{"bedrock toolConfig.Tools", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"systemTool":{"name":"nova_grounding"}}],"Tools":[]}}`},
		{"gemini TOOLS", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"googleSearch":{}}],"TOOLS":null}`},
		{"a tools entry with Type and type", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"Type":"function","type":"mcp","name":"f"}]}`},
		{"chat functions and Functions", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"f"}],"Functions":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ad, err := NewRegistry().GetAdapter(tc.format)
			require.NoError(t, err)
			req, err := ad.DecodeRequest([]byte(tc.body))
			require.NoError(t, err)
			_, ok := UnmodelledTools(ad, []byte(tc.body), req)
			assert.False(t, ok)
			assert.True(t, HasAmbiguousKeys(tc.format, []byte(tc.body)))
		})
	}
}

func TestUnmodelledToolsReadsKindsAndSecondLists(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		format Format
		body   string
		want   []UnmodelledTool
	}{
		{"type matched ignoring case", FormatOpenAIResponses, `{"model":"m","input":"hi","tools":[{"Type":"mcp","name":"f","server_url":"https://x"}]}`, []UnmodelledTool{{Kind: "mcp", Name: "f"}}},
		{"chat legacy functions", FormatOpenAI, `{"model":"m","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"a"},{"name":"b"}]}`, []UnmodelledTool{{Kind: "functions", Name: "a"}, {Kind: "functions", Name: "b"}}},
		{"anthropic mcp servers", FormatAnthropic, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"mcp_servers":[{"type":"url","url":"https://x","name":"gh"}]}`, []UnmodelledTool{{Kind: "mcp_servers", Name: "gh"}}},
		{"gemini mixed object counts per key", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}],"googleSearch":{},"codeExecution":{}}]}`, []UnmodelledTool{{Kind: "googleSearch"}, {Kind: "codeExecution"}}},
		{"gemini snake case declarations are modelled", FormatGemini, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"function_declarations":[{"name":"a"}]}]}`, nil},
		{"bedrock system tool", FormatBedrock, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"systemTool":{"name":"nova_grounding"}}]}}`, []UnmodelledTool{{Kind: "systemTool:nova_grounding"}}},
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
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestServerToolTypes(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"tools":[` +
		`{"type":"web_search_20250305","name":"web_search","max_uses":5},{"name":"f","input_schema":{"type":"object"}},{"type":"custom","name":"g","input_schema":{"type":"object"}}]}`)
	reg := NewRegistry()
	ad, err := reg.GetAdapter(FormatAnthropic)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"web_search": {"web_search_20250305"}}, ServerToolTypes(ad, body))
	responses, err := reg.GetAdapter(FormatOpenAIResponses)
	require.NoError(t, err)
	assert.Nil(t, ServerToolTypes(responses, []byte(`{"model":"m","input":"hi","tools":[{"type":"mcp","name":"f"}]}`)))
}

func TestGeminiDecodesSnakeCaseDeclarations(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"function_declarations":[{"name":"a","parameters":{"type":"OBJECT"}}]},{"functionDeclarations":[{"name":"b"}]}]}`
	req, err := NewRegistry().DecodeRequestFor([]byte(body), FormatGemini)
	require.NoError(t, err)
	require.Len(t, req.Tools, 2)
	assert.Equal(t, []string{"a", "b"}, []string{req.Tools[0].Name, req.Tools[1].Name})
}

func TestGraftSecondToolLists(t *testing.T) {
	t.Parallel()
	keep := func(names ...string) GraftOptions {
		return GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool {
			for _, n := range names {
				if u.Name == n {
					return true
				}
			}
			return false
		}}
	}
	const chat = `{"model":"m","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"a"},{"name":"b"}],"function_call":{"name":"b"}}`
	t.Run("a refused function goes with the call naming it", func(t *testing.T) {
		t.Parallel()
		out, _ := graftWith(t, FormatOpenAI, chat, keep("a"), func(*CanonicalRequest) {})
		assert.Equal(t, `{"model":"m","messages":[{"role":"user","content":"hi"}],"functions":[{"name":"a"}]}`, string(out))
	})
	t.Run("none left drops the key", func(t *testing.T) {
		t.Parallel()
		out, _ := graftWith(t, FormatOpenAI, chat, keep(), func(*CanonicalRequest) {})
		assert.Equal(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, string(out))
	})
	t.Run("kept functions stay as they came", func(t *testing.T) {
		t.Parallel()
		out, _ := graftWith(t, FormatOpenAI, chat, keep("a", "b"), func(*CanonicalRequest) {})
		assert.Equal(t, chat, string(out))
	})
	t.Run("no option leaves the list alone", func(t *testing.T) {
		t.Parallel()
		out, _ := graftWith(t, FormatOpenAI, chat, GraftOptions{}, func(*CanonicalRequest) {})
		assert.Equal(t, chat, string(out))
	})
	t.Run("anthropic mcp servers", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"mcp_servers":[{"type":"url","url":"https://x","name":"gh"}]}`
		out, _ := graftWith(t, FormatAnthropic, body, keep(), func(*CanonicalRequest) {})
		assert.Equal(t, `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`, string(out))
	})
}

func TestGraftSplitsMixedGeminiToolObjects(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"},{"name":"b"}],"googleSearch":{},"codeExecution":{}}]}`
	opts := GraftOptions{KeepUnmodelledTool: func(u UnmodelledTool) bool { return u.Kind == "googleSearch" }}
	out, _ := graftWith(t, FormatGemini, body, opts, func(r *CanonicalRequest) { r.Tools = r.Tools[:1] })
	assert.Equal(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"}]},{"googleSearch":{}}]}`, string(out))

	out, _ = graftWith(t, FormatGemini, body, opts, func(*CanonicalRequest) {})
	assert.Equal(t, `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"a"},{"name":"b"}]},{"googleSearch":{}}]}`, string(out))
}

func TestGraftRewritesAToolChoiceThatNamedARemovedTool(t *testing.T) {
	t.Parallel()
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[` +
		`{"type":"function","function":{"name":"a","parameters":{"type":"object"}}},{"type":"function","function":{"name":"b","parameters":{"type":"object"}}}],` +
		`"tool_choice":{"type":"function","function":{"name":"b"}},"n":1}`
	out, _ := graftWith(t, FormatOpenAI, body, GraftOptions{}, func(r *CanonicalRequest) {
		r.Tools = r.Tools[:1]
		DropDanglingToolChoice(r)
	})
	assert.Equal(t, `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[`+
		`{"type":"function","function":{"name":"a","parameters":{"type":"object"}}}],"tool_choice":"auto","n":1}`, string(out))
}

func TestDropDanglingToolChoice(t *testing.T) {
	t.Parallel()
	req := &CanonicalRequest{Tools: []CanonicalTool{{Name: "a"}}, ToolChoice: &CanonicalToolChoice{Type: "tool", Name: "a"}}
	DropDanglingToolChoice(req)
	assert.Equal(t, &CanonicalToolChoice{Type: "tool", Name: "a"}, req.ToolChoice)
	req.ToolChoice.Name = "gone"
	DropDanglingToolChoice(req)
	assert.Equal(t, &CanonicalToolChoice{Type: "auto"}, req.ToolChoice)
	req.ToolChoice = &CanonicalToolChoice{Type: "none"}
	DropDanglingToolChoice(req)
	assert.Equal(t, &CanonicalToolChoice{Type: "none"}, req.ToolChoice)
}

func TestReencodeCarriesStorageKeys(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		format  Format
		body    string
		carried []string
		dropped []string
	}{
		{
			name:    "responses",
			format:  FormatOpenAIResponses,
			body:    `{"model":"gpt-5","store":false,"previous_response_id":"resp_1","include":["reasoning.encrypted_content"],"reasoning":{"effort":"low"},"metadata":{"who":"bob@x.io"},"input":"hi bob@x.io"}`,
			carried: []string{`"store":false`, `"previous_response_id":"resp_1"`, `"include":["reasoning.encrypted_content"]`, `"reasoning":{"effort":"low"}`},
			dropped: []string{"metadata"},
		},
		{
			name:    "chat",
			format:  FormatOpenAI,
			body:    `{"model":"gpt-4o","store":false,"metadata":{"who":"bob@x.io"},"messages":[{"role":"user","content":"hi bob@x.io"}]}`,
			carried: []string{`"store":false`},
			dropped: []string{"metadata"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := NewRegistry()
			req, err := reg.DecodeRequestFor([]byte(tc.body), tc.format)
			require.NoError(t, err)
			req.Messages[0].Content = "hi [EMAIL]"
			ad, err := reg.GetAdapter(tc.format)
			require.NoError(t, err)
			out, err := ad.EncodeRequest(req)
			require.NoError(t, err)
			for _, want := range tc.carried {
				assert.Contains(t, string(out), want)
			}
			for _, key := range tc.dropped {
				assert.NotContains(t, string(out), key)
			}
			assert.NotContains(t, string(out), "bob@x.io")
		})
	}
	t.Run("not across formats", func(t *testing.T) {
		t.Parallel()
		body := `{"model":"gpt-5","store":false,"previous_response_id":"resp_1","input":"hi"}`
		out, err := NewRegistry().AdaptRequest([]byte(body), FormatOpenAIResponses, FormatAnthropic)
		require.NoError(t, err)
		assert.NotContains(t, string(out), "store")
		assert.NotContains(t, string(out), "resp_1")
	})
}

func periodicLines(size, lines int) (before, after string) {
	line := strings.Repeat("x ", size/lines/2-2)
	var b, a strings.Builder
	for i := 0; i < lines; i++ {
		b.WriteString(line + "  \n")
		a.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	return b.String(), a.String()
}

func TestDiffTextStaysFastOnRepetitiveText(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing")
	}
	for _, size := range []int{1 << 20, 7 << 20} {
		for _, lines := range []int{1, 100, 250} {
			before, after := periodicLines(size, lines)
			if lines == 1 {
				after = strings.Replace(before, "x x", "x  x", 300)
			}
			var took time.Duration
			for i := 0; i < 3; i++ {
				start := time.Now()
				_, _ = diffText(before, after)
				took = shortest(took, time.Since(start))
			}
			assert.Less(t, took, 50*time.Millisecond, "size=%d lines=%d", size, lines)
		}
	}
}

func TestDiffTextPlacesSpreadEditsInPlainText(t *testing.T) {
	t.Parallel()
	words := strings.Fields("the quick brown fox jumps over a lazy dog while seven wizards quietly judge boxing matches near old rivers")
	var sb strings.Builder
	for i := 0; sb.Len() < 1<<20; i++ {
		if i%4000 == 2000 {
			fmt.Fprintf(&sb, "mail bob%d@corp.example now ", i)
			continue
		}
		sb.WriteString(words[(i*7+i/len(words))%len(words)])
		sb.WriteByte(' ')
	}
	before := sb.String()
	after := before
	for i := 0; strings.Contains(after, "@corp.example"); i++ {
		at := strings.Index(after, "@corp.example")
		start := strings.LastIndex(after[:at], " ") + 1
		after = after[:start] + "[EMAIL]" + after[at+len("@corp.example"):]
	}
	hunks, ok := diffText(before, after)
	require.True(t, ok)
	require.Greater(t, len(hunks), 40)
	assert.Equal(t, strings.Count(before, "@corp.example"), len(hunks))
}

func TestGraftCostOnALargeBodyWithinCaps(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("timing")
	}
	var sb strings.Builder
	sb.WriteString(`{"model":"gpt-5","input":"hi","tools":[`)
	for i := 0; sb.Len() < 7<<20; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"type":"function","name":"t%d","parameters":{"type":"object","x":{"a":{"a":"%s"}}}}`, i, strings.Repeat("z", 180))
	}
	sb.WriteString(`]}`)
	body := []byte(sb.String())
	root, err := rawRoot(body)
	require.NoError(t, err)
	require.True(t, rawWithinCaps(body[root.start:root.end]))
	require.LessOrEqual(t, len(body), maxGraftBody)
	ad, err := NewRegistry().GetAdapter(FormatOpenAIResponses)
	require.NoError(t, err)

	roundTrip, graft := time.Duration(0), time.Duration(0)
	var out []byte
	for i := 0; i < 3; i++ {
		start := time.Now()
		req, err := ad.DecodeRequest(body)
		require.NoError(t, err)
		_, err = ad.EncodeRequest(req)
		require.NoError(t, err)
		d := time.Since(start)
		roundTrip = shortest(roundTrip, d)

		baseline := req.Clone()
		req.Tools = req.Tools[1:]
		start = time.Now()
		out, err = GraftChangedFields(ad, body, baseline, req)
		require.NoError(t, err)
		graft = shortest(graft, time.Since(start))
	}
	t.Logf("graft %v, decode and encode %v", graft, roundTrip)
	assert.Less(t, graft, 3*roundTrip)
	assert.True(t, strings.HasPrefix(string(out), `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"t1",`))
	var decoded map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &decoded))
}

func shortest(a, b time.Duration) time.Duration {
	if a == 0 || b < a {
		return b
	}
	return a
}
