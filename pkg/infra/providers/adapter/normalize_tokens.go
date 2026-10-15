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

import "encoding/json"

func normalizeMaxCompletionTokens(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	maxTokens, ok := raw["max_tokens"]
	if !ok {
		return body
	}
	if existing, ok := raw["max_completion_tokens"]; ok && !isEmptyOrNull(existing) {
		delete(raw, "max_tokens")
		return marshalOrOriginal(raw, body)
	}
	var n int
	if err := json.Unmarshal(maxTokens, &n); err != nil || n <= 0 {
		return body
	}
	raw["max_completion_tokens"] = maxTokens
	delete(raw, "max_tokens")
	return marshalOrOriginal(raw, body)
}

var maxOutputTokenFields = []string{"max_completion_tokens", "max_tokens", "max_output_tokens"}

// ClampMaxOutputTokens lowers the first present output-token field to limit
// when the requested value exceeds it. The body is unchanged when the field
// is absent, unparseable, not positive, or already within the limit.
func ClampMaxOutputTokens(body []byte, limit int) (out []byte, requested int, clamped bool) {
	if limit <= 0 || len(body) == 0 {
		return body, 0, false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, 0, false
	}
	field := ""
	var n int
	for _, name := range maxOutputTokenFields {
		rawN, ok := raw[name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(rawN, &n); err != nil || n <= 0 {
			return body, 0, false
		}
		field = name
		break
	}
	if field == "" || n <= limit {
		return body, n, false
	}
	encoded, err := json.Marshal(limit)
	if err != nil {
		return body, n, false
	}
	raw[field] = encoded
	out = marshalOrOriginal(raw, body)
	return out, n, true
}

func marshalOrOriginal(raw map[string]json.RawMessage, original []byte) []byte {
	out, err := json.Marshal(raw)
	if err != nil {
		return original
	}
	return out
}
