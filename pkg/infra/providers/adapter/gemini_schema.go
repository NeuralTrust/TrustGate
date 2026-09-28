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

import "strings"

// geminiSchemaAllowlist is the intersection of Gemini API v1beta Schema fields
// (RUN-1515). Unknown keys 400 the request, so an incomplete allowlist fails closed.
var geminiSchemaAllowlist = map[string]struct{}{
	"type": {}, "format": {}, "title": {}, "description": {}, "nullable": {},
	"enum": {}, "items": {}, "minItems": {}, "maxItems": {}, "properties": {},
	"required": {}, "minProperties": {}, "maxProperties": {}, "minLength": {},
	"maxLength": {}, "pattern": {}, "minimum": {}, "maximum": {}, "anyOf": {},
	"propertyOrdering": {}, "default": {}, "example": {},
}

const geminiRefDepthLimit = 8

func sanitizeGeminiParameters(root map[string]interface{}) map[string]interface{} {
	if root == nil {
		return map[string]interface{}{"type": "OBJECT"}
	}
	defs := map[string]interface{}{}
	if raw, ok := root["$defs"].(map[string]interface{}); ok {
		defs = raw
	} else if raw, ok := root["definitions"].(map[string]interface{}); ok {
		defs = raw
	}
	out := sanitizeGeminiSchemaNode(root, defs, nil, 0)
	if out == nil {
		out = map[string]interface{}{}
	}
	if _, ok := out["type"]; !ok {
		out["type"] = "OBJECT"
	}
	return out
}

func sanitizeGeminiSchemaNode(node map[string]interface{}, defs map[string]interface{}, stack []string, depth int) map[string]interface{} {
	if node == nil {
		return nil
	}
	if depth > geminiRefDepthLimit {
		return typedObjectLeaf(node)
	}
	if ref, ok := node["$ref"].(string); ok {
		return resolveGeminiRef(ref, node, defs, stack, depth)
	}
	out := map[string]interface{}{}
	if allOf, ok := node["allOf"].([]interface{}); ok {
		out = mergeAllOf(allOf, defs, stack, depth)
	}
	copyGeminiScalars(node, out)
	if props, ok := node["properties"].(map[string]interface{}); ok {
		copied := make(map[string]interface{}, len(props))
		for name, raw := range props {
			if child, ok := raw.(map[string]interface{}); ok {
				copied[name] = sanitizeGeminiSchemaNode(child, defs, stack, depth+1)
			} else {
				copied[name] = raw
			}
		}
		out["properties"] = copied
	}
	if items, ok := node["items"]; ok {
		out["items"] = sanitizeItems(items, defs, stack, depth)
	}
	anyOf := collectAnyOf(node)
	if len(anyOf) > 0 {
		branches := make([]interface{}, 0, len(anyOf))
		for _, raw := range anyOf {
			if child, ok := raw.(map[string]interface{}); ok {
				branches = append(branches, sanitizeGeminiSchemaNode(child, defs, stack, depth+1))
			}
		}
		if len(branches) > 0 {
			out["anyOf"] = branches
		}
	}
	copyLiteralList(node, out, "required")
	copyLiteralList(node, out, "enum")
	copyLiteralList(node, out, "propertyOrdering")
	if _, hasEnum := out["enum"]; !hasEnum {
		if c, ok := node["const"]; ok {
			out["enum"] = []interface{}{c}
		}
	}
	if _, hasEx := out["example"]; !hasEx {
		if examples, ok := node["examples"].([]interface{}); ok && len(examples) > 0 {
			out["example"] = examples[0]
		}
	}
	if _, hasMin := out["minimum"]; !hasMin {
		if v, ok := node["exclusiveMinimum"]; ok {
			out["minimum"] = v
		}
	}
	if _, hasMax := out["maximum"]; !hasMax {
		if v, ok := node["exclusiveMaximum"]; ok {
			out["maximum"] = v
		}
	}
	normalizeGeminiType(out)
	return out
}

func copyGeminiScalars(node, out map[string]interface{}) {
	for _, k := range []string{"type", "title", "description", "format", "nullable", "pattern", "minItems", "maxItems", "minProperties", "maxProperties", "minLength", "maxLength", "minimum", "maximum", "default", "example"} {
		if v, ok := node[k]; ok {
			if _, allowed := geminiSchemaAllowlist[k]; allowed {
				out[k] = v
			}
		}
	}
}

func copyLiteralList(node, out map[string]interface{}, key string) {
	raw, ok := node[key]
	if !ok {
		return
	}
	if list, ok := raw.([]interface{}); ok {
		out[key] = append([]interface{}{}, list...)
	}
}

func sanitizeItems(items interface{}, defs map[string]interface{}, stack []string, depth int) interface{} {
	switch v := items.(type) {
	case map[string]interface{}:
		return sanitizeGeminiSchemaNode(v, defs, stack, depth+1)
	case []interface{}:
		if len(v) > 0 {
			if child, ok := v[0].(map[string]interface{}); ok {
				return sanitizeGeminiSchemaNode(child, defs, stack, depth+1)
			}
		}
	}
	return items
}

func collectAnyOf(node map[string]interface{}) []interface{} {
	var out []interface{}
	if v, ok := node["anyOf"].([]interface{}); ok {
		out = append(out, v...)
	}
	if v, ok := node["oneOf"].([]interface{}); ok {
		out = append(out, v...)
	}
	return out
}

func mergeAllOf(branches []interface{}, defs map[string]interface{}, stack []string, depth int) map[string]interface{} {
	out := map[string]interface{}{}
	props := map[string]interface{}{}
	var required []interface{}
	for _, raw := range branches {
		child, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		sanitized := sanitizeGeminiSchemaNode(child, defs, stack, depth+1)
		for k, v := range sanitized {
			switch k {
			case "properties":
				if m, ok := v.(map[string]interface{}); ok {
					for name, schema := range m {
						props[name] = schema
					}
				}
			case "required":
				if list, ok := v.([]interface{}); ok {
					required = append(required, list...)
				}
			default:
				if _, exists := out[k]; !exists {
					out[k] = v
				}
			}
		}
	}
	if len(props) > 0 {
		out["properties"] = props
	}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func resolveGeminiRef(ref string, siblings map[string]interface{}, defs map[string]interface{}, stack []string, depth int) map[string]interface{} {
	name := strings.TrimPrefix(ref, "#/$defs/")
	name = strings.TrimPrefix(name, "#/definitions/")
	if name == ref || name == "" {
		return typedObjectLeaf(siblings)
	}
	for _, seen := range stack {
		if seen == name {
			return typedObjectLeaf(siblings)
		}
	}
	target, ok := defs[name].(map[string]interface{})
	if !ok {
		return typedObjectLeaf(siblings)
	}
	merged := map[string]interface{}{}
	for k, v := range target {
		merged[k] = v
	}
	for k, v := range siblings {
		if k == "$ref" {
			continue
		}
		merged[k] = v
	}
	return sanitizeGeminiSchemaNode(merged, defs, append(stack, name), depth+1)
}

func typedObjectLeaf(siblings map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{"type": "OBJECT"}
	if siblings != nil {
		if d, ok := siblings["description"]; ok {
			out["description"] = d
		}
	}
	return out
}

func normalizeGeminiType(out map[string]interface{}) {
	raw, ok := out["type"]
	if !ok {
		return
	}
	switch v := raw.(type) {
	case string:
		if mapped, found := jsonSchemaToGeminiType[strings.ToLower(v)]; found {
			out["type"] = mapped
			return
		}
		if _, found := geminiToJSONSchemaType[v]; found {
			out["type"] = v
			return
		}
		delete(out, "type")
	case []interface{}:
		var first string
		nullable := false
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if strings.EqualFold(s, "null") {
				nullable = true
				continue
			}
			if first == "" {
				first = s
			}
		}
		if first == "" && nullable {
			out["type"] = "NULL"
			return
		}
		if mapped, found := jsonSchemaToGeminiType[strings.ToLower(first)]; found {
			out["type"] = mapped
		} else {
			delete(out, "type")
		}
		if nullable {
			out["nullable"] = true
		}
	}
}
