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

func marshalOrOriginal(raw map[string]json.RawMessage, original []byte) []byte {
	out, err := json.Marshal(raw)
	if err != nil {
		return original
	}
	return out
}
