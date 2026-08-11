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

package trustguard

import (
	"encoding/json"
	"testing"
)

func TestMCPInputText(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "name and nested arguments",
			body: `{"name":"search","arguments":{"query":"secret token","filters":{"lang":"en"},"tags":["a","b"],"limit":10,"safe":true}}`,
			want: "search\nen\nsecret token\na\nb",
		},
		{
			name: "arguments only",
			body: `{"name":"","arguments":{"prompt":"hello"}}`,
			want: "hello",
		},
		{
			name: "name only with empty arguments",
			body: `{"name":"ping","arguments":{}}`,
			want: "ping",
		},
		{
			name: "name only with no arguments field",
			body: `{"name":"ping"}`,
			want: "ping",
		},
		{
			name: "undecodable arguments fall back to raw",
			body: `{"name":"tool","arguments":"not-json"}`,
			want: "tool\nnot-json",
		},
		{
			name: "non-string leaves skipped",
			body: `{"name":"calc","arguments":{"a":1,"b":2.5,"c":null,"d":false}}`,
			want: "calc",
		},
		{
			name: "empty body",
			body: ``,
			want: "",
		},
		{
			name: "malformed body",
			body: `{`,
			want: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mcpInputText([]byte(tc.body)); got != tc.want {
				t.Fatalf("mcpInputText(%s) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestMCPOutputText(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "single text block",
			body: `{"content":[{"type":"text","text":"hello"}],"isError":false}`,
			want: "hello",
		},
		{
			name: "multiple text blocks concatenated",
			body: `{"content":[{"type":"text","text":"line one"},{"type":"text","text":"line two"}]}`,
			want: "line one\nline two",
		},
		{
			name: "isError true still extracts",
			body: `{"content":[{"type":"text","text":"boom"}],"isError":true}`,
			want: "boom",
		},
		{
			name: "non-text blocks ignored",
			body: `{"content":[{"type":"image","text":"ignored"},{"type":"resource"}]}`,
			want: "",
		},
		{
			name: "mixed text and non-text",
			body: `{"content":[{"type":"image"},{"type":"text","text":"keep"}]}`,
			want: "keep",
		},
		{
			name: "empty content",
			body: `{"content":[],"isError":false}`,
			want: "",
		},
		{
			name: "structuredContent only, no text blocks",
			body: `{"content":[],"structuredContent":{"email":"jane@acme.io"}}`,
			want: "jane@acme.io",
		},
		{
			name: "structuredContent appended after text blocks in sorted-key order",
			body: `{"content":[{"type":"text","text":"body"}],"structuredContent":{"b":"second","a":"first"}}`,
			want: "body\nfirst\nsecond",
		},
		{
			name: "structuredContent numbers and bools skipped",
			body: `{"content":[],"structuredContent":{"count":3,"ok":true,"name":"Jane"}}`,
			want: "Jane",
		},
		{
			name: "malformed json",
			body: `{"content":`,
			want: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mcpOutputText([]byte(tc.body)); got != tc.want {
				t.Fatalf("mcpOutputText(%s) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestRewriteMCPResponseMasksStructuredContent(t *testing.T) {
	t.Parallel()

	t.Run("text block and structuredContent leaves together", func(t *testing.T) {
		t.Parallel()
		body := `{"content":[{"type":"text","text":"contact"}],"structuredContent":{"b":"second","a":"first"},"isError":false}`
		// Same order mcpOutputText builds: text block, then structured leaves
		// sorted by key (a before b). TrustGuard returns the joined masked text.
		masked := "CONTACT\nONE\nTWO"

		out, ok := rewriteMCPResponse([]byte(body), masked)
		if !ok {
			t.Fatal("rewriteMCPResponse returned false")
		}
		var got mcpToolResult
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal rewritten body: %v", err)
		}
		if len(got.Content) != 1 || got.Content[0].Text != "CONTACT" {
			t.Fatalf("content not rewritten: %+v", got.Content)
		}
		var sc map[string]string
		if err := json.Unmarshal(got.StructuredContent, &sc); err != nil {
			t.Fatalf("unmarshal structuredContent: %v", err)
		}
		if sc["a"] != "ONE" || sc["b"] != "TWO" {
			t.Fatalf("structuredContent not rewritten: %+v", sc)
		}
	})

	t.Run("structuredContent only", func(t *testing.T) {
		t.Parallel()
		body := `{"content":[],"structuredContent":{"email":"jane@acme.io"}}`
		masked := "[MASKED_EMAIL]"

		out, ok := rewriteMCPResponse([]byte(body), masked)
		if !ok {
			t.Fatal("rewriteMCPResponse returned false")
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal rewritten body: %v", err)
		}
		sc, _ := got["structuredContent"].(map[string]any)
		if sc["email"] != "[MASKED_EMAIL]" {
			t.Fatalf("structuredContent email not masked: %+v", sc)
		}
	})

	t.Run("line-count mismatch fails closed", func(t *testing.T) {
		t.Parallel()
		body := `{"content":[],"structuredContent":{"email":"jane@acme.io"}}`
		// Masked text has an extra line the original never had: the mapping is
		// ambiguous, so the rewrite must refuse rather than corrupt the body.
		if _, ok := rewriteMCPResponse([]byte(body), "one\ntwo"); ok {
			t.Fatal("expected rewriteMCPResponse to fail on a line-count mismatch")
		}
	})
}

func TestFlattenArgumentStrings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "flat map sorted by key", raw: `{"b":"second","a":"first"}`, want: []string{"first", "second"}},
		{name: "nested map", raw: `{"outer":{"inner":"deep"}}`, want: []string{"deep"}},
		{name: "array of strings", raw: `["x","y","z"]`, want: []string{"x", "y", "z"}},
		{name: "mixed types skip non-strings", raw: `{"s":"keep","n":42,"b":true,"z":null}`, want: []string{"keep"}},
		{name: "empty object", raw: `{}`, want: nil},
		{name: "empty raw", raw: ``, want: nil},
		{name: "undecodable raw fallback", raw: `not-json`, want: []string{"not-json"}},
		{name: "whitespace strings skipped", raw: `{"a":"  ","b":"real"}`, want: []string{"real"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := flattenArgumentStrings(json.RawMessage(tc.raw))
			if len(got) != len(tc.want) {
				t.Fatalf("flattenArgumentStrings(%s) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("flattenArgumentStrings(%s)[%d] = %q, want %q", tc.raw, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestMCPToolsCallPayload(t *testing.T) {
	t.Parallel()
	raw, err := mcpToolsCallPayload([]byte(`{"name":"search","arguments":{"query":"find me"}}`))
	if err != nil {
		t.Fatalf("mcpToolsCallPayload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["jsonrpc"] != "2.0" || m["method"] != "tools/call" {
		t.Fatalf("envelope = %#v", m)
	}
	params, _ := m["params"].(map[string]any)
	if params["name"] != "search" {
		t.Fatalf("name = %#v", params["name"])
	}
}

func TestMCPToolsResultPayload(t *testing.T) {
	t.Parallel()
	raw, err := mcpToolsResultPayload([]byte(`{"content":[{"type":"text","text":"ok"}],"isError":false}`))
	if err != nil {
		t.Fatalf("mcpToolsResultPayload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["jsonrpc"] != "2.0" {
		t.Fatalf("jsonrpc = %#v", m["jsonrpc"])
	}
	if _, ok := m["result"]; !ok {
		t.Fatalf("missing result: %#v", m)
	}
}
