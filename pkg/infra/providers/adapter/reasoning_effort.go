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

import (
	"encoding/json"
	"strings"
)

// reasoningEffortNoneRejected are Chat Completions model families that answer
// 400 to reasoning_effort "none". GPT-5.6 and GPT-6 Sol/Luna accept it, and
// need it for function tools; GPT-6 Astra and GPT-6.1 Sol do not.
var reasoningEffortNoneRejected = []string{
	"gpt-6-astra",
	"gpt-6.1-sol",
}

// ModelRejectsReasoningEffortNone reports whether model refuses
// reasoning_effort "none". Matching follows the model id the provider sees,
// including a vendor prefix, a fine-tune wrapper, and a dated snapshot.
func ModelRejectsReasoningEffortNone(model string) bool {
	stem := chatModelStem(model)
	if stem == "" {
		return false
	}
	for _, family := range reasoningEffortNoneRejected {
		if modelHasPrefix(stem, family) {
			return true
		}
	}
	return false
}

// OmitUnsupportedReasoningEffort drops reasoning_effort "none" when model
// rejects that value. A request that did not set the field is left unchanged,
// and every other effort value is kept.
func OmitUnsupportedReasoningEffort(body []byte, model string) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	effort, ok := raw["reasoning_effort"]
	if !ok || isEmptyOrNull(effort) {
		return body
	}
	var value string
	if err := json.Unmarshal(effort, &value); err != nil || !strings.EqualFold(strings.TrimSpace(value), "none") {
		return body
	}
	if !ModelRejectsReasoningEffortNone(model) {
		return body
	}
	delete(raw, "reasoning_effort")
	return marshalOrOriginal(raw, body)
}

// chatModelStem is the model id without a vendor prefix or fine-tune wrapper,
// lowercased, so family checks see "gpt-6.1-sol" in "openai/gpt-6.1-sol" and
// "ft:gpt-6.1-sol:org::id".
func chatModelStem(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	if i := strings.LastIndexByte(model, '/'); i >= 0 {
		model = model[i+1:]
	}
	model, _, _ = strings.Cut(strings.TrimPrefix(model, "ft:"), ":")
	return model
}

func modelHasPrefix(model, prefix string) bool {
	if !strings.HasPrefix(model, prefix) {
		return false
	}
	if len(model) == len(prefix) {
		return true
	}
	switch model[len(prefix)] {
	case '-', '.', ':':
		return true
	default:
		return false
	}
}
