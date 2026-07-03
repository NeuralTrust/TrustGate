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

package tool_call_validation

import (
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	degradedReasonUnsupportedFormat = "redact_unsupported_format"
	degradedReasonRedactFailed      = "redact_failed"
)

func redactSupportsFormat(format adapter.Format) bool {
	return format.IsOpenAIFamily()
}

type redaction struct {
	callIndex   int
	path        string
	whole       bool
	replaceWith string
	terms       []string
}

func applyRedactions(body []byte, format adapter.Format, reds []redaction) ([]byte, bool) {
	if len(reds) == 0 {
		return body, false
	}
	byIndex := make(map[int][]redaction, len(reds))
	for _, r := range reds {
		byIndex[r.callIndex] = append(byIndex[r.callIndex], r)
	}
	switch {
	case format == adapter.FormatOpenAIResponses:
		return patchResponsesBody(body, byIndex)
	case adapter.IsSameWireFormat(format, adapter.FormatOpenAI):
		return patchCompletionsBody(body, byIndex)
	default:
		return body, false
	}
}

func patchCompletionsBody(body []byte, byIndex map[int][]redaction) ([]byte, bool) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false
	}
	choicesRaw, ok := root["choices"]
	if !ok {
		return body, false
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(choicesRaw, &choices); err != nil || len(choices) == 0 {
		return body, false
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &choice); err != nil {
		return body, false
	}
	messageRaw, ok := choice["message"]
	if !ok {
		return body, false
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(messageRaw, &message); err != nil {
		return body, false
	}
	toolCallsRaw, ok := message["tool_calls"]
	if !ok {
		return body, false
	}
	var toolCalls []json.RawMessage
	if err := json.Unmarshal(toolCallsRaw, &toolCalls); err != nil {
		return body, false
	}

	changed := false
	for idx, reds := range byIndex {
		if idx < 0 || idx >= len(toolCalls) {
			continue
		}
		patched, ok := patchCompletionsToolCall(toolCalls[idx], reds)
		if !ok {
			continue
		}
		toolCalls[idx] = patched
		changed = true
	}
	if !changed {
		return body, false
	}

	var err error
	if message["tool_calls"], err = json.Marshal(toolCalls); err != nil {
		return body, false
	}
	if choice["message"], err = json.Marshal(message); err != nil {
		return body, false
	}
	if choices[0], err = json.Marshal(choice); err != nil {
		return body, false
	}
	if root["choices"], err = json.Marshal(choices); err != nil {
		return body, false
	}
	out, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return out, true
}

func patchCompletionsToolCall(raw json.RawMessage, reds []redaction) (json.RawMessage, bool) {
	var toolCall map[string]json.RawMessage
	if err := json.Unmarshal(raw, &toolCall); err != nil {
		return nil, false
	}
	fnRaw, ok := toolCall["function"]
	if !ok {
		return nil, false
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(fnRaw, &fn); err != nil {
		return nil, false
	}
	newArgs, ok := patchArgumentsToken(fn["arguments"], reds)
	if !ok {
		return nil, false
	}
	var err error
	fn["arguments"] = newArgs
	if toolCall["function"], err = json.Marshal(fn); err != nil {
		return nil, false
	}
	encoded, err := json.Marshal(toolCall)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func patchResponsesBody(body []byte, byIndex map[int][]redaction) ([]byte, bool) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false
	}
	outputRaw, ok := root["output"]
	if !ok {
		return body, false
	}
	var output []json.RawMessage
	if err := json.Unmarshal(outputRaw, &output); err != nil {
		return body, false
	}

	changed := false
	callIndex := -1
	for i := range output {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(output[i], &item); err != nil {
			continue
		}
		var itemType string
		if raw, ok := item["type"]; ok {
			_ = json.Unmarshal(raw, &itemType)
		}
		if itemType != "function_call" {
			continue
		}
		callIndex++
		reds, ok := byIndex[callIndex]
		if !ok {
			continue
		}
		newArgs, ok := patchArgumentsToken(item["arguments"], reds)
		if !ok {
			continue
		}
		item["arguments"] = newArgs
		encoded, err := json.Marshal(item)
		if err != nil {
			continue
		}
		output[i] = encoded
		changed = true
	}
	if !changed {
		return body, false
	}

	var err error
	if root["output"], err = json.Marshal(output); err != nil {
		return body, false
	}
	out, err := json.Marshal(root)
	if err != nil {
		return body, false
	}
	return out, true
}

func patchArgumentsToken(raw json.RawMessage, reds []redaction) (json.RawMessage, bool) {
	if raw == nil {
		return nil, false
	}
	var argsStr string
	if err := json.Unmarshal(raw, &argsStr); err != nil {
		return nil, false
	}
	mutated, ok := mutateArguments(argsStr, reds)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(mutated)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

func mutateArguments(argsStr string, reds []redaction) (string, bool) {
	var obj any
	if err := json.Unmarshal([]byte(argsStr), &obj); err != nil {
		return "", false
	}
	changed := false
	for _, r := range reds {
		cur, ok := getAtPath(obj, r.path)
		if !ok {
			continue
		}
		current, ok := cur.(string)
		if !ok {
			continue
		}
		next := redactValue(current, r)
		if next == current {
			continue
		}
		if setAtPath(obj, r.path, next) {
			changed = true
		}
	}
	if !changed {
		return "", false
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return "", false
	}
	return string(out), true
}

func redactValue(value string, r redaction) string {
	if r.whole {
		return r.replaceWith
	}
	result := value
	for _, term := range r.terms {
		if term == "" {
			continue
		}
		result = strings.ReplaceAll(result, term, r.replaceWith)
	}
	return result
}
