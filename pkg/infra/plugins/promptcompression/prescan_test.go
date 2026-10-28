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

package promptcompression

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prescanFragments are the pieces generated texts are made of: everything a
// transform reacts to, next to near misses.
var prescanFragments = []string{
	"a", "word", " ", "  ", "\t", "\n", "\n\n", "\n\n\n", "\r\n", "\x1b[31m", "\x1b[0m",
	"{", "}", "[", "]", `"`, ":", ",", " , ", "```json\n", "\n```", "```", "json",
	`{"a": 1}`, `{"a":1}`, `[1, 2]`, `[INFO]`, "{name}", "\xc3\xa9", "\xc2\xa0", "\xe2\x80\xa8",
	"<b>", "&", `\`, `\n`, "null", "0",
}

func randomText(rng *rand.Rand) string {
	var b strings.Builder
	for range rng.IntN(9) {
		b.WriteString(prescanFragments[rng.IntN(len(prescanFragments))])
	}
	return b.String()
}

func randomArgs(rng *rand.Rand) any {
	v := map[string]any{"q": randomText(rng), "n": rng.IntN(100), "list": []any{randomText(rng), 1}}
	if rng.IntN(4) == 0 {
		return randomText(rng)
	}
	return v
}

// prescanBody builds one request of the given shape from texts t (at least
// four) and tool arguments, as a client would send it.
func prescanBody(shape int, t []string, args any) (format string, payload map[string]any) {
	argsJSON, _ := json.Marshal(args)
	if s, ok := args.(string); ok {
		argsJSON = []byte(s)
	}
	switch shape % 4 {
	case 0:
		return "openai", map[string]any{"model": "m", "messages": []any{
			map[string]any{"role": "system", "content": t[0]},
			map[string]any{"role": "user", "content": t[1]},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{
				"id": "c1", "type": "function", "function": map[string]any{"name": "f", "arguments": string(argsJSON)},
			}}},
			map[string]any{"role": "tool", "tool_call_id": "c1", "content": t[2]},
			map[string]any{"role": "assistant", "content": t[3]},
		}}
	case 1:
		return "openai", map[string]any{"model": "m", "messages": []any{
			map[string]any{"role": "system", "content": []any{
				map[string]any{"type": "text", "text": t[0]}, map[string]any{"type": "text", "text": t[1]},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "text", "text": t[2]}, map[string]any{"type": "text", "text": t[3]},
				map[string]any{"type": "text", "text": t[0]},
			}},
		}}
	case 2:
		return "anthropic", map[string]any{"model": "m", "max_tokens": 10, "system": t[0], "messages": []any{
			map[string]any{"role": "user", "content": t[1]},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "text", "text": t[2]},
				map[string]any{"type": "tool_use", "id": "t1", "name": "f", "input": args},
				map[string]any{"type": "text", "text": t[3]},
			}},
			map[string]any{"role": "user", "content": "next"},
		}}
	default:
		return "anthropic", map[string]any{"model": "m", "max_tokens": 10,
			"system": []any{map[string]any{"type": "text", "text": t[0]}, map[string]any{"type": "text", "text": t[1]}},
			"messages": []any{map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "text", "text": t[2]}, map[string]any{"type": "text", "text": t[3]},
			}}},
		}
	}
}

// prescanEncodings serialize a payload the ways clients do: compact with or
// without HTML escaping, indented, and with string characters written as
// unicode escapes.
func prescanEncodings(t testing.TB, rng *rand.Rand, payload map[string]any) [][]byte {
	t.Helper()
	compact, err := json.Marshal(payload)
	require.NoError(t, err)
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	require.NoError(t, enc.Encode(payload))
	indented, err := json.MarshalIndent(payload, "", "  ")
	require.NoError(t, err)
	return [][]byte{compact, bytes.TrimSpace(plain.Bytes()), indented, unicodeEscaped(compact, rng)}
}

// unicodeEscaped rewrites a random share of the ASCII characters inside
// strings as six-byte unicode escapes, short escapes included.
func unicodeEscaped(b []byte, rng *rand.Rand) []byte {
	short := map[byte]byte{'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f', '/': '/'}
	var out bytes.Buffer
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			if r, ok := short[b[i+1]]; ok && rng.IntN(2) == 0 {
				fmt.Fprintf(&out, "\\u%04x", r)
				i++
				continue
			}
			out.WriteByte(c)
			out.WriteByte(b[i+1])
			i++
			continue
		case c < 0x80 && rng.IntN(3) == 0:
			fmt.Fprintf(&out, "\\u%04X", c)
			continue
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}

var prescanConfigs = []map[string]any{
	{"min_length": 0},
	{"min_length": 0, "max_consecutive_blank_lines": 2},
	{"min_length": 0, "normalize_whitespace": false, "strip_ansi": false},
	{"min_length": 0, "compress_json": false, "strip_ansi": false},
	{"min_length": 0, "compress_json": false, "normalize_whitespace": false},
	{"min_length": 12},
	{"min_length": 30},
	{"min_length": 60},
	{},
}

// assertNoMissedChange fails when the transforms change body but
// mayCompress said they could not.
func assertNoMissedChange(t testing.TB, format string, body []byte, cfg Settings) {
	t.Helper()
	reg := adapter.NewRegistry()
	f := adapter.Format(format)
	creq, err := reg.DecodeRequestFor(body, f)
	if err != nil || creq == nil {
		return
	}
	_, changed, err := rewriteRequest(reg, f, body, creq, cfg)
	if err != nil || !changed {
		return
	}
	if !mayCompress(body, cfg) {
		t.Fatalf("mayCompress missed a change\nsettings: %+v\nbody: %s", cfg, body)
	}
}

func TestMayCompressNeverMissesAChange(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	for range 4000 {
		texts := []string{randomText(rng), randomText(rng), randomText(rng), randomText(rng)}
		format, payload := prescanBody(rng.IntN(4), texts, randomArgs(rng))
		for _, body := range prescanEncodings(t, rng, payload) {
			for _, set := range prescanConfigs {
				cfg, err := parseConfig(set)
				require.NoError(t, err)
				assertNoMissedChange(t, format, body, cfg)
			}
		}
	}
}

func FuzzMayCompress(f *testing.F) {
	f.Add("hello \nworld", "{\"a\": 1}", "\n\n\nx", "\x1b[31mred", 0, uint64(1))
	f.Add("", "\n", "\nabc", "```json\n{ }\n```", 1, uint64(2))
	f.Add("{\"a\":1}", "", "x\n", "\n\ny", 3, uint64(3))
	f.Fuzz(func(t *testing.T, a, b, c, d string, shape int, seed uint64) {
		rng := rand.New(rand.NewPCG(seed, 7))
		texts := []string{a, b, c, d}
		args := any(map[string]any{"q": c, "r": []any{d, 1}})
		if shape&4 != 0 {
			args = a
		}
		format, payload := prescanBody(shape, texts, args)
		if _, err := json.Marshal(payload); err != nil {
			return
		}
		for _, body := range prescanEncodings(t, rng, payload) {
			for _, set := range prescanConfigs {
				cfg, err := parseConfig(set)
				require.NoError(t, err)
				assertNoMissedChange(t, format, body, cfg)
			}
		}
	})
}

func TestMayCompressPassesCleanRequests(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(map[string]any{})
	require.NoError(t, err)
	long := strings.TrimSpace(strings.Repeat("Plain prose without anything to compress. ", 20))
	cases := map[string]string{
		"chat":              `{"model":"gpt-4o","messages":[{"role":"system","content":"` + long + `"},{"role":"user","content":"` + long + `"}]}`,
		"spaced separators": `{"model": "gpt-4o", "messages": [{"role": "user", "content": "` + long + `\n\nNext paragraph."}]}`,
		"short tool arguments": `{"model":"gpt-4o","messages":[{"role":"user","content":"run it"},` +
			`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"command\": \"ls -la\"}"}}]},` +
			`{"role":"tool","tool_call_id":"c1","content":"total 0\nfile.txt\n"}]}`,
		"compact json result": `{"model":"gpt-4o","messages":[{"role":"tool","tool_call_id":"c1","content":"{\"ok\":true,\"items\":[1,2,3]}"}]}`,
		"log lines":           `{"model":"gpt-4o","messages":[{"role":"user","content":"[INFO] started\n[WARN] slow disk\n{name} is a template"}]}`,
		"anthropic small tool input": `{"model":"claude","max_tokens":64,"messages":[{"role":"assistant","content":[` +
			`{"type":"text","text":"Checking."},{"type":"tool_use","id":"t1","name":"bash","input": {"command": "ls"}}]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.True(t, json.Valid([]byte(body)))
			assert.False(t, mayCompress([]byte(body), cfg))
		})
	}
}

func TestMayCompressFlagsEachTransform(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(map[string]any{"min_length": 0})
	require.NoError(t, err)
	cases := map[string]string{
		"ansi":                  `{"messages":[{"role":"user","content":"\u001b[31mred"}]}`,
		"trailing space":        `{"messages":[{"role":"user","content":"line \nnext"}]}`,
		"space at end":          `{"messages":[{"role":"user","content":"end "}]}`,
		"blank run":             `{"messages":[{"role":"user","content":"a\n\n\nb"}]}`,
		"escaped newlines":      `{"messages":[{"role":"user","content":"a\u000a\u000A\nb"}]}`,
		"blank run across join": `{"messages":[{"role":"user","content":[{"type":"text","text":"a\n"},{"type":"text","text":"\nb"}]}]}`,
		"pretty json":           `{"messages":[{"role":"tool","content":"{\n  \"a\": 1\n}"}]}`,
		"json after empty part": `{"messages":[{"role":"user","content":[{"type":"text","text":""},{"type":"text","text":"{\"a\":1}"}]}]}`,
		"fenced json":           "{\"messages\":[{\"role\":\"user\",\"content\":\"see ```json\\n{\\\"a\\\":1}\\n```\"}]}",
		"spaced arguments":      `{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"f","arguments":"{\"a\": 1}"}}]}]}`,
		"indented tool input":   `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"f","input":{ "a": 1 }}]}]}`,
		"two system messages":   `{"messages":[{"role":"system","content":"a"},{"role":"developer","content":"b"}]}`,
		"malformed":             `{"messages":[{"role":"user","content":"unterminated`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.True(t, mayCompress([]byte(body), cfg))
		})
	}
}

func TestExecuteSkipsPipelineWhenNothingToCompress(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + strings.TrimSpace(strings.Repeat("clean text ", 40)) + `"}]}`)
	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce,
		map[string]any{}, reqCtx(openAIProvider, "", body), newEvent()))
	require.NoError(t, err)
	assert.Nil(t, res.RequestBody)
	assert.Equal(t, []string{decisionNoChange}, res.Headers[headerDecision])
}
