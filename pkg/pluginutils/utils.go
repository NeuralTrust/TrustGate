package pluginutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func DefineRequestBody(body []byte, mappingField string) ([]byte, error) {
	wrapDefault := func(b []byte) ([]byte, error) {
		return json.Marshal(map[string]interface{}{
			"input": string(b),
		})
	}

	var root map[string]interface{}
	if err := json.Unmarshal(body, &root); err != nil || mappingField == "" {
		return wrapDefault(body)
	}

	current := any(root)
	segments := strings.Split(mappingField, ".")

	indexRe := regexp.MustCompile(`^(?P<key>[^\[]+)(?P<idx>\[(?P<num>-?\d+)\])?$`)

	for _, seg := range segments {
		m := indexRe.FindStringSubmatch(seg)
		if len(m) == 0 {
			return wrapDefault(body)
		}
		key := m[1]
		idxStr := m[3]

		obj, ok := current.(map[string]interface{})
		if !ok {
			return wrapDefault(body)
		}
		next, exists := obj[key]
		if !exists {
			return wrapDefault(body)
		}

		// If no index, descend directly
		if idxStr == "" {
			current = next
			continue
		}

		// Handle array index
		arr, ok := next.([]interface{})
		if !ok {
			return wrapDefault(body)
		}
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return wrapDefault(body)
		}
		if idx < 0 {
			idx = len(arr) + idx // -1 => last element
		}
		if idx < 0 || idx >= len(arr) {
			return wrapDefault(body)
		}
		current = arr[idx]
	}

	// Marshal the final value to string if not already a string
	var input string
	switch v := current.(type) {
	case string:
		input = v
	default:
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(v); err != nil {
			return nil, fmt.Errorf("failed to stringify extracted value: %w", err)
		}
		input = buf.String()
	}

	res, err := json.Marshal(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapped input: %w", err)
	}
	return res, nil
}
