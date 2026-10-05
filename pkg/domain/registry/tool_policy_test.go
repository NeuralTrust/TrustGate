// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"encoding/json"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestToolPolicy_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		policy  ToolPolicy
		wantErr bool
	}{
		{name: "auto", policy: ToolPolicyAuto},
		{name: "pinned", policy: ToolPolicyPinned},
		{name: "empty is not valid until normalized", policy: "", wantErr: true},
		{name: "unknown", policy: "strict", wantErr: true},
		{name: "wrong case is not valid until normalized", policy: "Pinned", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want a validation error", err)
			}
		})
	}
}

func TestToolPolicy_Normalize(t *testing.T) {
	t.Parallel()
	tests := map[ToolPolicy]ToolPolicy{
		"":         ToolPolicyAuto,
		"  ":       ToolPolicyAuto,
		"auto":     ToolPolicyAuto,
		" PINNED ": ToolPolicyPinned,
		"bogus":    "bogus",
	}
	for in, want := range tests {
		if got := in.Normalize(); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistry_Validate_ToolPolicy(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("new MCP registry defaults to auto", func(t *testing.T) {
		t.Parallel()
		b, err := NewMCPRegistry(gwID, "mcp", "", validMCPTarget())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.ToolPolicy != ToolPolicyAuto {
			t.Fatalf("ToolPolicy = %q, want auto", b.ToolPolicy)
		}
	})

	t.Run("empty policy is defaulted to auto", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp", "", validMCPTarget())
		b.ToolPolicy = ""
		if err := b.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.ToolPolicy != ToolPolicyAuto {
			t.Fatalf("ToolPolicy = %q, want auto", b.ToolPolicy)
		}
	})

	t.Run("pinned MCP registry is valid", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp", "", validMCPTarget())
		b.ToolPolicy = ToolPolicyPinned
		if err := b.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unknown policy is rejected", func(t *testing.T) {
		t.Parallel()
		b, _ := NewMCPRegistry(gwID, "mcp", "", validMCPTarget())
		b.ToolPolicy = "strict"
		if err := b.Validate(); !errors.Is(err, ErrInvalidToolPolicy) {
			t.Fatalf("err = %v, want ErrInvalidToolPolicy", err)
		}
	})

	t.Run("pinned LLM registry is rejected", func(t *testing.T) {
		t.Parallel()
		b, err := NewLLMRegistry(gwID, "llm", "", &LLMTarget{Provider: "openai", Auth: NewAPIKeyAuth("sk-test")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b.ToolPolicy = ToolPolicyPinned
		if err := b.Validate(); !errors.Is(err, ErrInvalidToolPolicy) {
			t.Fatalf("err = %v, want ErrInvalidToolPolicy", err)
		}
	})
}

func TestFingerprint(t *testing.T) {
	t.Parallel()
	base := Fingerprint("search", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"}},"required":["q"]}`))

	t.Run("is a 64 char hex sha256", func(t *testing.T) {
		t.Parallel()
		if len(base) != 64 {
			t.Fatalf("len = %d, want 64", len(base))
		}
	})

	same := map[string]json.RawMessage{
		"key order, nested":  json.RawMessage(`{"required":["q"],"properties":{"n":{"type":"integer"},"q":{"type":"string"}},"type":"object"}`),
		"whitespace":         json.RawMessage("{\n  \"type\": \"object\",\n  \"properties\": { \"q\": {\"type\":\"string\"}, \"n\": {\"type\":\"integer\"} },\n  \"required\": [ \"q\" ]\n}\n"),
		"surrounding spaces": json.RawMessage(`  {"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"}},"required":["q"]}  `),
	}
	for name, schema := range same {
		t.Run("same: "+name, func(t *testing.T) {
			t.Parallel()
			if got := Fingerprint("search", "Search the web", schema); got != base {
				t.Fatalf("fingerprint differs: %s vs %s", got, base)
			}
		})
	}

	different := map[string]string{
		"name":           Fingerprint("search2", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"}},"required":["q"]}`)),
		"description":    Fingerprint("search", "Search the web.", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"}},"required":["q"]}`)),
		"schema type":    Fingerprint("search", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"number"}},"required":["q"]}`)),
		"array order":    Fingerprint("search", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"}},"required":["q","n"]}`)),
		"extra property": Fingerprint("search", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"},"n":{"type":"integer"},"z":{"type":"string"}},"required":["q"]}`)),
	}
	for name, got := range different {
		t.Run("different: "+name, func(t *testing.T) {
			t.Parallel()
			if got == base {
				t.Fatalf("fingerprint did not change for a different %s", name)
			}
		})
	}

	t.Run("nil, empty, null and {} schemas are equal", func(t *testing.T) {
		t.Parallel()
		want := Fingerprint("t", "d", json.RawMessage(`{}`))
		for _, schema := range []json.RawMessage{nil, {}, json.RawMessage(`null`), json.RawMessage(" \n "), json.RawMessage(` { } `)} {
			if got := Fingerprint("t", "d", schema); got != want {
				t.Fatalf("schema %q hashed differently from {}", schema)
			}
		}
	})

	t.Run("name and description do not collide across the boundary", func(t *testing.T) {
		t.Parallel()
		a := Fingerprint("ab", "c", nil)
		b := Fingerprint("a", "bc", nil)
		if a == b {
			t.Fatal("name/description boundary collided")
		}
	})

	t.Run("html characters are not escaped", func(t *testing.T) {
		t.Parallel()
		escaped := Fingerprint("t", `a\u003cb`, nil)
		raw := Fingerprint("t", "a<b", nil)
		if escaped == raw {
			t.Fatal("a literal backslash-u003c must not equal the < character")
		}
	})

	t.Run("invalid schema is deterministic and distinct from {}", func(t *testing.T) {
		t.Parallel()
		bad := json.RawMessage(`{"type":`)
		first := Fingerprint("t", "d", bad)
		second := Fingerprint("t", "d", bad)
		if first != second {
			t.Fatal("not deterministic")
		}
		if first == Fingerprint("t", "d", json.RawMessage(`{}`)) {
			t.Fatal("invalid schema collided with {}")
		}
	})

	t.Run("number literal text is preserved", func(t *testing.T) {
		t.Parallel()
		// A numeric constraint widened from 10 to 10.0 is a textual change the
		// pin treats as a change; large ints must not lose precision either.
		a := Fingerprint("t", "d", json.RawMessage(`{"maximum":9007199254740993}`))
		b := Fingerprint("t", "d", json.RawMessage(`{"maximum":9007199254740992}`))
		if a == b {
			t.Fatal("large integers collapsed to the same float64")
		}
	})
}

// TestFingerprint_GoldenValue pins the exact digest. Stored rows are keyed by
// it, so changing the canonical form re-pends every tool of every pinned
// registry; that must be a deliberate, reviewed act.
func TestFingerprint_GoldenValue(t *testing.T) {
	t.Parallel()
	got := Fingerprint("search", "Search", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`))
	const want = "5b7c061dc5e2cb868de33a1a21e5df5e58817b04d9225d9c846c2808207ca5c0"
	if got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
}

func TestNewToolCandidate_FingerprintAndDefinitionShareOneCanonicalForm(t *testing.T) {
	t.Parallel()
	schema := json.RawMessage(`{ "type": "object", "properties": {"b":{}, "a":{}} }`)
	c, err := NewToolCandidate("search", "Search", schema)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.Fingerprint != Fingerprint("search", "Search", schema) {
		t.Fatal("candidate fingerprint differs from Fingerprint")
	}
	if got := fingerprintOf(c.Definition); got != c.Fingerprint {
		t.Fatalf("hash of stored definition = %s, want %s", got, c.Fingerprint)
	}
	const want = `{"description":"Search","inputSchema":{"properties":{"a":{},"b":{}},"type":"object"},"name":"search"}`
	if string(c.Definition) != want {
		t.Fatalf("definition = %s, want %s", c.Definition, want)
	}
	if !json.Valid(CanonicalDefinition("t", "d", json.RawMessage(`{"type":`))) {
		t.Fatal("definition of an invalid schema must still be valid JSON")
	}
}

func TestNewToolCandidate_RejectsNUL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, tool, desc string
		schema           json.RawMessage
		wantErr          bool
	}{
		{name: "clean", tool: "t", desc: "d", schema: json.RawMessage(`{"type":"object"}`)},
		{name: "nul in name", tool: "a\x00b", desc: "d", wantErr: true},
		{name: "nul in description", tool: "t", desc: "a\x00b", wantErr: true},
		{name: "escaped nul in a schema value", tool: "t", desc: "d", schema: json.RawMessage(`{"description":"a\u0000b"}`), wantErr: true},
		{name: "escaped nul in a schema key", tool: "t", desc: "d", schema: json.RawMessage(`{"a\u0000b":1}`), wantErr: true},
		{name: "nul in an invalid schema", tool: "t", desc: "d", schema: json.RawMessage("{\"a\x00"), wantErr: true},
		{name: "literal backslash-u0000 text is not a NUL", tool: "t", desc: `a\u0000b`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewToolCandidate(tt.tool, tt.desc, tt.schema)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidToolDefinition) {
				t.Fatalf("err = %v, want ErrInvalidToolDefinition", err)
			}
		})
	}
}

func TestFingerprint_InvalidSchemaDoesNotCollideWithAStringSchema(t *testing.T) {
	t.Parallel()
	invalid := Fingerprint("t", "d", json.RawMessage(`foo`))
	for _, valid := range []string{`"foo"`, `"invalid:foo"`, `{"$invalid":"foo"}x`} {
		if invalid == Fingerprint("t", "d", json.RawMessage(valid)) {
			t.Fatalf("invalid schema collided with %s", valid)
		}
	}
}
