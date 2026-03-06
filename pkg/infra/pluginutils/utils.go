package pluginutils

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var segmentRe = regexp.MustCompile(`^([^\[]+)(?:\[(-?\d+)\])?$`)

type MappingContent struct {
	Input string `json:"input"`
}

func DefineRequestBody(body []byte, mappingField string, clean bool) (*MappingContent, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil {
		return &MappingContent{Input: string(body)}, nil
	}

	toClean := func(v interface{}) (*MappingContent, error) {
		var parts []string
		collectText(&parts, v)
		return &MappingContent{Input: strings.Join(parts, " ")}, nil
	}
	fallback := func() (*MappingContent, error) {
		if clean {
			return toClean(root)
		}
		return &MappingContent{Input: string(body)}, nil
	}

	if mappingField == "" {
		return fallback()
	}

	current := any(root)
	for _, seg := range strings.Split(mappingField, ".") {
		m := segmentRe.FindStringSubmatch(seg)
		if len(m) == 0 {
			return fallback()
		}
		key := m[1]

		obj, ok := current.(map[string]interface{})
		if !ok {
			return fallback()
		}
		next, exists := obj[key]
		if !exists {
			return fallback()
		}

		if m[2] == "" {
			current = next
			continue
		}

		arr, ok := next.([]interface{})
		if !ok {
			return fallback()
		}
		idx, err := strconv.Atoi(m[2])
		if err != nil {
			return fallback()
		}
		if idx < 0 {
			idx = len(arr) + idx
		}
		if idx < 0 || idx >= len(arr) {
			return fallback()
		}
		current = arr[idx]
	}

	if clean {
		return toClean(current)
	}

	var input string
	switch v := current.(type) {
	case string:
		input = v
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to stringify extracted value: %w", err)
		}
		input = string(data)
	}

	return &MappingContent{Input: input}, nil
}

// ExtractText takes a string that may contain JSON (possibly nested/escaped)
// and returns only the human-readable text: all keys and string values,
// joined by spaces. Non-JSON strings are returned as-is.
func ExtractText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Try to parse as JSON object or array.
	var raw interface{}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return s
	}

	// If it unmarshalled to a plain string, not a structured JSON.
	if _, ok := raw.(string); ok {
		return s
	}

	var parts []string
	collectText(&parts, raw)
	return strings.Join(parts, " ")
}

// CleanInputs applies ExtractText to every element of the slice.
func CleanInputs(inputs []string) []string {
	out := make([]string, len(inputs))
	for i, s := range inputs {
		out[i] = ExtractText(s)
	}
	return out
}

func collectText(parts *[]string, v interface{}) {
	switch val := v.(type) {
	case string:
		// The string itself might be escaped JSON — try to recurse.
		trimmed := strings.TrimSpace(val)
		if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
			var inner interface{}
			if err := json.Unmarshal([]byte(trimmed), &inner); err == nil {
				if _, ok := inner.(string); !ok {
					collectText(parts, inner)
					return
				}
			}
		}
		if trimmed != "" {
			*parts = append(*parts, strings.ReplaceAll(trimmed, "_", " "))
		}
	case map[string]interface{}:
		for k, child := range val {
			*parts = append(*parts, strings.ReplaceAll(k, "_", " "))
			collectText(parts, child)
		}
	case []interface{}:
		for _, child := range val {
			collectText(parts, child)
		}
	case float64, bool:
		// skip numbers and booleans
	}
}
