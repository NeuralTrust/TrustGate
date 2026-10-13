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
	"bytes"
	"context"
	"encoding/json"
)

// Upstreams are spoken to in 2026-07-28, where a tool's outputSchema may be any
// JSON Schema and its structuredContent any JSON value. Older revisions require
// both to be objects, and the TypeScript SDK rejects a whole tools/list over a
// single tool that breaks that rule (ENG-1810). Clients on an older revision get
// tools without structured output; the result text still carries the value.

const typedOutputRevision = "2026-07-28"

type clientRevisionKey struct{}

// WithClientRevision records the protocol revision the caller declared in its
// MCP-Protocol-Version header. Clients before 2025-06-18 send none, which reads
// as an older revision.
func WithClientRevision(ctx context.Context, revision string) context.Context {
	return context.WithValue(ctx, clientRevisionKey{}, revision)
}

// ClientAcceptsTypedOutput reports whether the caller speaks 2026-07-28 or
// later, where outputSchema and structuredContent need not be objects.
func ClientAcceptsTypedOutput(ctx context.Context) bool {
	revision, _ := ctx.Value(clientRevisionKey{}).(string)
	return revision >= typedOutputRevision
}

// withObjectOutputSchema drops an outputSchema whose root is not type "object",
// reporting whether it did.
func withObjectOutputSchema(t Tool) (Tool, bool) {
	schema, ok := t.payload["outputSchema"]
	if !ok || rootTypeIsObject(schema) {
		return t, false
	}
	t.payload = clonePayload(t.payload)
	delete(t.payload, "outputSchema")
	return t, true
}

func rootTypeIsObject(schema json.RawMessage) bool {
	var root struct {
		Type json.RawMessage `json:"type"`
	}
	if err := json.Unmarshal(schema, &root); err != nil {
		return false
	}
	var typ string
	return json.Unmarshal(root.Type, &typ) == nil && typ == "object"
}

// withObjectStructuredContent drops a structuredContent that is not a JSON
// object. When the result has no content of its own, the value moves into a
// text block so the caller does not lose it.
func withObjectStructuredContent(result json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil || fields == nil {
		return result
	}
	structured, ok := fields["structuredContent"]
	if !ok || isJSONObject(structured) {
		return result
	}
	delete(fields, "structuredContent")
	if !hasContentBlocks(fields["content"]) {
		fields["content"] = textContent(structured)
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return result
	}
	return out
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func hasContentBlocks(raw json.RawMessage) bool {
	var blocks []json.RawMessage
	return json.Unmarshal(raw, &blocks) == nil && len(blocks) > 0
}

func textContent(value json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return json.RawMessage(`[]`)
	}
	encoded, err := json.Marshal([]map[string]string{{"type": "text", "text": string(trimmed)}})
	if err != nil {
		return json.RawMessage(`[]`)
	}
	return encoded
}
