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

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func attributeTool(t Tool, reg *registrydomain.Registry) Tool {
	label := registryLabel(reg)
	if label == "" {
		return t
	}
	t.payload = clonePayload(t.payload)
	putStringField(t.payload, "title", qualifyDisplay(label, stringField(t.payload, "title"), t.Name))
	if desc := stringField(t.payload, "description"); desc != "" {
		putStringField(t.payload, "description", qualifyDescription(label, desc))
	}
	qualifyObjectTitle(t.payload, "annotations", label, t.Name)
	return t
}

func attributePrompt(p Prompt, reg *registrydomain.Registry) Prompt {
	label := registryLabel(reg)
	if label == "" {
		return p
	}
	p.payload = clonePayload(p.payload)
	putStringField(p.payload, "title", qualifyDisplay(label, stringField(p.payload, "title"), p.Name))
	if desc := stringField(p.payload, "description"); desc != "" {
		putStringField(p.payload, "description", qualifyDescription(label, desc))
	}
	return p
}

func registryLabel(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	if n := strings.TrimSpace(reg.Name); n != "" {
		return humanizeRegistryLabel(n)
	}
	if reg.MCPTarget != nil {
		if c := strings.TrimSpace(reg.MCPTarget.Code); c != "" {
			return humanizeRegistryLabel(c)
		}
	}
	return ""
}

func humanizeRegistryLabel(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/"); i >= 0 && i+1 < len(s) {
		return s[i+1:]
	}
	return s
}

func qualifyDisplay(label, current, fallback string) string {
	label = strings.TrimSpace(label)
	current = strings.TrimSpace(current)
	if current == "" {
		current = strings.TrimSpace(fallback)
	}
	if label == "" {
		return current
	}
	prefix := label + ": "
	if current == "" {
		return strings.TrimSuffix(prefix, ": ")
	}
	if strings.HasPrefix(current, prefix) {
		return current
	}
	return prefix + current
}

func qualifyDescription(label, desc string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return desc
	}
	tag := "[" + label + "] "
	if strings.HasPrefix(desc, tag) {
		return desc
	}
	return tag + desc
}

func clonePayload(payload map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(payload)+2)
	for k, v := range payload {
		out[k] = v
	}
	return out
}

func putStringField(payload map[string]json.RawMessage, key, value string) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	payload[key] = raw
}

func qualifyObjectTitle(payload map[string]json.RawMessage, objectKey, label, fallback string) {
	raw, ok := payload[objectKey]
	if !ok {
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return
	}
	current := stringField(obj, "title")
	if current == "" {
		return
	}
	obj = clonePayload(obj)
	putStringField(obj, "title", qualifyDisplay(label, current, fallback))
	encoded, err := json.Marshal(obj)
	if err != nil {
		return
	}
	payload[objectKey] = encoded
}
