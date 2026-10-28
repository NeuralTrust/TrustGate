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
)

// BedrockInvokeRequestFormat names the wire format an InvokeModel body is written
// in when the gateway also speaks it: Anthropic Messages, OpenAI chat or Converse.
// For any other body it returns false and the name of the model-native shape
// (prompt, titan, cohere_chat or unknown), which no gateway format models.
func BedrockInvokeRequestFormat(body []byte) (Format, string, bool) {
	fields, ok := jsonFields(body)
	if !ok {
		return "", "unknown", false
	}
	switch sniffInvokeRequest(fields) {
	case shapeAnthropic:
		return FormatAnthropic, "anthropic", true
	case shapeOpenAI:
		return FormatOpenAI, "openai", true
	case shapeConverse:
		return FormatBedrock, "converse", true
	case shapeTitan:
		return "", "titan", false
	case shapePrompt:
		return "", "prompt", false
	case shapeCohereChat:
		return "", "cohere_chat", false
	default:
		return "", "unknown", false
	}
}

// PatchTopLevelFields rewrites top-level fields of the JSON object in body in
// place: each key of set replaces the value of that field, or is appended when
// absent, and each key of remove is deleted. Every other byte of body, key order
// and whitespace included, is kept, so a relayed body changes only where the
// edit is.
func PatchTopLevelFields(body []byte, set map[string]json.RawMessage, remove []string) ([]byte, error) {
	root, err := rawRoot(body)
	if err != nil {
		return nil, err
	}
	edits := make(map[string]topEdit, len(set)+len(remove))
	for k, v := range set {
		edits[k] = topEdit{value: v}
	}
	for _, k := range remove {
		edits[k] = topEdit{remove: true}
	}
	patches, ok := rawObjectEdits(body, root, edits)
	if !ok {
		return nil, errRawJSON
	}
	return applyRawPatches(body, patches)
}
