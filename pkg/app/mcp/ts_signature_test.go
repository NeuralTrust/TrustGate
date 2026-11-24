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

package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToolSignature(t *testing.T) {
	t.Parallel()
	for label, tc := range map[string]struct {
		input, output string
		want          string
	}{
		"required and optional, in the schema's order": {
			input: `{"type":"object","properties":{"issueId":{"type":"string"},"body":{"type":"string"},"internal":{"type":"boolean"}},"required":["issueId","body"]}`,
			want:  `t(args: { issueId: string; body: string; internal?: boolean }): Promise<unknown>`,
		},
		"enum, array and nested object": {
			input: `{"type":"object","properties":{"state":{"enum":["open","closed"]},"labels":{"type":"array","items":{"type":"string"}},"page":{"type":"object","properties":{"size":{"type":"integer"}}}}}`,
			want:  `t(args: { state?: "open" | "closed"; labels?: string[]; page?: { size?: number } }): Promise<unknown>`,
		},
		"nullable through a type list": {
			input: `{"type":"object","properties":{"due":{"type":["string","null"]}}}`,
			want:  `t(args: { due?: string | null }): Promise<unknown>`,
		},
		"a key that is not an identifier is quoted": {
			input: `{"type":"object","properties":{"x-api-version":{"type":"string"}}}`,
			want:  `t(args: { "x-api-version"?: string }): Promise<unknown>`,
		},
		"free-form object": {
			input: `{"type":"object","additionalProperties":{"type":"number"}}`,
			want:  `t(args: Record<string, number>): Promise<unknown>`,
		},
		"no schema": {
			want: `t(args: {}): Promise<unknown>`,
		},
		// The result type comes only from a declared outputSchema.
		"declared output": {
			input:  `{"type":"object","properties":{}}`,
			output: `{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`,
			want:   `t(args: Record<string, unknown>): Promise<{ id: string }>`,
		},
		// What the translation does not understand is unknown, never guessed.
		"a $ref is unknown": {
			input: `{"type":"object","properties":{"filter":{"$ref":"#/$defs/Filter"}}}`,
			want:  `t(args: { filter?: unknown }): Promise<unknown>`,
		},
		"a union with something unknown is unknown": {
			input: `{"type":"object","properties":{"v":{"anyOf":[{"type":"string"},{"$ref":"#/x"}]}}}`,
			want:  `t(args: { v?: unknown }): Promise<unknown>`,
		},
	} {
		got := toolSignature("t", json.RawMessage(tc.input), json.RawMessage(tc.output))
		if got != tc.want {
			t.Fatalf("%s:\n got %s\nwant %s", label, got, tc.want)
		}
	}
}

func TestToolSignature_IsBounded(t *testing.T) {
	t.Parallel()
	var props []string
	for i := 0; i < 200; i++ {
		props = append(props, `"field_`+strings.Repeat("x", 10)+string(rune('a'+i%26))+`_`+strings.Repeat("y", i%7)+`":{"type":"string"}`)
	}
	input := `{"type":"object","properties":{` + strings.Join(props, ",") + `}}`
	got := toolSignature("big", json.RawMessage(input), nil)
	if len(got) > maxSignatureLength {
		t.Fatalf("signature is %d bytes, want at most %d", len(got), maxSignatureLength)
	}
	if got != "big(args: object): Promise<unknown>" {
		t.Fatalf("got %s", got)
	}
}
