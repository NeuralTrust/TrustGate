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
