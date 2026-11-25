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
	"encoding/json"
	"regexp"
	"strings"
)

// A tool's signature in TypeScript, written from its JSON Schema.
//
// Models read a TypeScript signature more reliably than the schema it comes
// from, and it is a fraction of the size. It is a convenience, never the
// contract: the full input schema always travels next to it in a tool's
// detail, and whatever the translation does not understand is written as
// unknown rather than guessed. A result type is only given when the tool
// declares an outputSchema; most do not, and inventing one is how a caller
// ends up reading fields that are not there.

const (
	maxSignatureDepth = 4
	maxUnionMembers   = 8
	// maxSignatureLength bounds one signature. A schema too large to read at a
	// glance is summarised; its detail still carries the schema.
	maxSignatureLength = 1200
)

var tsIdentifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// toolSignature is name(args: {...}): Promise<...> for one tool.
func toolSignature(name string, input, output json.RawMessage) string {
	args := "{}"
	if len(bytes.TrimSpace(input)) > 0 {
		args = schemaToTS(input, 0)
		if args == "unknown" {
			args = "Record<string, unknown>"
		}
	}
	result := "unknown"
	if len(bytes.TrimSpace(output)) > 0 && !bytes.Equal(bytes.TrimSpace(output), []byte("null")) {
		result = schemaToTS(output, 0)
	}
	signature := name + "(args: " + args + "): Promise<" + result + ">"
	if len(signature) > maxSignatureLength {
		signature = name + "(args: object): Promise<" + shortType(result) + ">"
	}
	return signature
}

func shortType(t string) string {
	if len(t) > 80 {
		return "object"
	}
	return t
}

// schemaToTS translates one JSON Schema into a TypeScript type.
func schemaToTS(raw json.RawMessage, depth int) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("true")) {
		return "unknown"
	}
	if bytes.Equal(raw, []byte("false")) {
		return "never"
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schema); err != nil {
		return "unknown"
	}
	if depth > maxSignatureDepth {
		return "unknown"
	}
	if values, ok := schema["enum"]; ok {
		if t := literalUnion(values); t != "" {
			return t
		}
	}
	if value, ok := schema["const"]; ok {
		if t := literalType(value); t != "" {
			return t
		}
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		if members, ok := schema[key]; ok {
			if t := unionOf(members, depth); t != "" {
				return t
			}
		}
	}
	if allOf, ok := schema["allOf"]; ok {
		var parts []json.RawMessage
		if err := json.Unmarshal(allOf, &parts); err == nil && len(parts) == 1 {
			return schemaToTS(parts[0], depth+1)
		}
		return "unknown"
	}
	types := schemaTypes(schema["type"])
	if len(types) == 0 {
		if _, hasProps := schema["properties"]; hasProps {
			types = []string{"object"}
		} else if _, hasItems := schema["items"]; hasItems {
			types = []string{"array"}
		}
	}
	if len(types) == 0 {
		return "unknown"
	}
	members := make([]string, 0, len(types))
	for _, typ := range types {
		members = append(members, typeToTS(typ, schema, depth))
	}
	return joinUnion(members)
}

func schemaTypes(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func typeToTS(typ string, schema map[string]json.RawMessage, depth int) string {
	switch typ {
	case "string":
		return "string"
	case "number", "integer":
		return "number"
	case "boolean":
		return "boolean"
	case "null":
		return "null"
	case "array":
		items := "unknown"
		if raw, ok := schema["items"]; ok {
			items = schemaToTS(raw, depth+1)
		}
		if strings.Contains(items, " | ") {
			items = "(" + items + ")"
		}
		return items + "[]"
	case "object":
		return objectToTS(schema, depth)
	default:
		return "unknown"
	}
}

func objectToTS(schema map[string]json.RawMessage, depth int) string {
	rawProps, hasProps := schema["properties"]
	keys := orderedKeys(rawProps)
	if !hasProps || len(keys) == 0 {
		if extra, ok := schema["additionalProperties"]; ok {
			value := schemaToTS(extra, depth+1)
			if value == "never" {
				return "{}"
			}
			return "Record<string, " + value + ">"
		}
		return "Record<string, unknown>"
	}
	var props map[string]json.RawMessage
	if err := json.Unmarshal(rawProps, &props); err != nil {
		return "Record<string, unknown>"
	}
	required := make(map[string]struct{})
	var requiredList []string
	if raw, ok := schema["required"]; ok {
		_ = json.Unmarshal(raw, &requiredList)
		for _, name := range requiredList {
			required[name] = struct{}{}
		}
	}
	var b strings.Builder
	b.WriteString("{ ")
	for i, key := range keys {
		if i > 0 {
			b.WriteString("; ")
		}
		if tsIdentifier.MatchString(key) {
			b.WriteString(key)
		} else {
			quoted, _ := json.Marshal(key)
			b.Write(quoted)
		}
		if _, ok := required[key]; !ok {
			b.WriteString("?")
		}
		b.WriteString(": ")
		b.WriteString(schemaToTS(props[key], depth+1))
	}
	b.WriteString(" }")
	return b.String()
}

func literalUnion(raw json.RawMessage) string {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || len(values) == 0 {
		return ""
	}
	if len(values) > maxUnionMembers {
		// A long enum reads as its type; the schema in the detail lists them.
		if t := literalBaseType(values[0]); t != "" {
			return t
		}
		return ""
	}
	members := make([]string, 0, len(values))
	for _, value := range values {
		t := literalType(value)
		if t == "" {
			return ""
		}
		members = append(members, t)
	}
	return joinUnion(members)
}

func literalType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"', 't', 'f', 'n', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		if !json.Valid(raw) {
			return ""
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return ""
		}
		return compact.String()
	default:
		return ""
	}
}

func literalBaseType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	default:
		if raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9') {
			return "number"
		}
		return ""
	}
}

func unionOf(raw json.RawMessage, depth int) string {
	var members []json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || len(members) == 0 {
		return ""
	}
	if len(members) > maxUnionMembers {
		return "unknown"
	}
	types := make([]string, 0, len(members))
	for _, member := range members {
		types = append(types, schemaToTS(member, depth+1))
	}
	return joinUnion(types)
}

func joinUnion(members []string) string {
	seen := make(map[string]struct{}, len(members))
	out := make([]string, 0, len(members))
	for _, member := range members {
		if member == "unknown" {
			return "unknown"
		}
		if _, dup := seen[member]; dup {
			continue
		}
		seen[member] = struct{}{}
		out = append(out, member)
	}
	return strings.Join(out, " | ")
}

// orderedKeys returns an object's keys in the order the schema wrote them, so
// a signature reads the way its server meant it and is the same every time.
func orderedKeys(raw json.RawMessage) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return keys
		}
		key, ok := tok.(string)
		if !ok {
			return keys
		}
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return keys
		}
	}
	return keys
}

// schemaParamNames are an input schema's top-level property names, which the
// ranking indexes: a tool that takes an issueId is about issues.
func schemaParamNames(raw json.RawMessage) []string {
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil
	}
	return orderedKeys(schema["properties"])
}
