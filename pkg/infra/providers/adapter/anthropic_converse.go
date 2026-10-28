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
	"fmt"
	"slices"
	"strings"
)

// converseAnthropicOnlyFields are the additionalModelRequestFields keys the
// Converse encoder writes for an Anthropic client, in the spelling only Claude
// models take.
var converseAnthropicOnlyFields = []string{"top_k"}

// AnthropicFieldsUnsupportedError reports Anthropic options sent to a Bedrock
// model of another family.
type AnthropicFieldsUnsupportedError struct {
	Model  string
	Fields []string
}

func (e *AnthropicFieldsUnsupportedError) Error() string {
	return fmt.Sprintf("%s only apply to Anthropic models on Bedrock, not to %s",
		strings.Join(e.Fields, ", "), e.Model)
}

// GateAnthropicConverseFields checks a Converse body translated from an
// Anthropic request against the model it is sent to. Claude models, and
// identifiers that hide the model, keep every field: Bedrock judges them
// itself. A model of another family gets an AnthropicFieldsUnsupportedError
// for the Claude-only fields and keeps the Converse ones (outputConfig, tool
// strict), which Bedrock judges. With drop, as on a fallback leg, every field
// the client's Anthropic options produced is removed instead and the removed
// names are returned, so a model the client did not choose still answers.
func GateAnthropicConverseFields(body []byte, model string, drop bool) ([]byte, []string, error) {
	vendor := BedrockModelVendor(model)
	if vendor == "" || vendor == "anthropic" {
		return body, nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, nil, nil
	}
	var fields map[string]json.RawMessage
	if additional, ok := raw["additionalModelRequestFields"]; ok {
		if err := json.Unmarshal(additional, &fields); err != nil {
			return body, nil, nil
		}
	}
	var found []string
	for _, key := range converseAnthropicOnlyFields {
		if _, ok := fields[key]; ok {
			found = append(found, key)
		}
	}
	if !drop {
		if len(found) > 0 {
			return body, nil, &AnthropicFieldsUnsupportedError{Model: model, Fields: found}
		}
		return body, nil, nil
	}
	dropped := found
	for _, key := range found {
		delete(fields, key)
	}
	if len(found) > 0 {
		if len(fields) == 0 {
			delete(raw, "additionalModelRequestFields")
		} else {
			encoded, err := json.Marshal(fields)
			if err != nil {
				return body, nil, err
			}
			raw["additionalModelRequestFields"] = encoded
		}
	}
	if _, ok := raw["outputConfig"]; ok {
		delete(raw, "outputConfig")
		dropped = append(dropped, "outputConfig")
	}
	toolConfig, stripped, err := withoutToolStrict(raw["toolConfig"])
	if err != nil {
		return body, nil, err
	}
	if stripped {
		raw["toolConfig"] = toolConfig
		dropped = append(dropped, "toolSpec.strict")
	}
	if len(dropped) == 0 {
		return body, nil, nil
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return body, nil, err
	}
	return out, dropped, nil
}

// withoutToolStrict removes strict from every toolSpec of a Converse
// toolConfig and reports whether one carried it.
func withoutToolStrict(toolConfig json.RawMessage) (json.RawMessage, bool, error) {
	var cfg map[string]json.RawMessage
	if json.Unmarshal(toolConfig, &cfg) != nil {
		return toolConfig, false, nil
	}
	var tools []map[string]json.RawMessage
	if json.Unmarshal(cfg["tools"], &tools) != nil {
		return toolConfig, false, nil
	}
	stripped := false
	for _, tool := range tools {
		var spec map[string]json.RawMessage
		if json.Unmarshal(tool["toolSpec"], &spec) != nil {
			continue
		}
		if _, ok := spec["strict"]; !ok {
			continue
		}
		delete(spec, "strict")
		encoded, err := json.Marshal(spec)
		if err != nil {
			return nil, false, err
		}
		tool["toolSpec"] = encoded
		stripped = true
	}
	if !stripped {
		return toolConfig, false, nil
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return nil, false, err
	}
	cfg["tools"] = encoded
	out, err := json.Marshal(cfg)
	return out, true, err
}

// anthropicConverseMapped are the Anthropic Messages top-level keys the
// Converse encoder carries over, and anthropicOutputConfigMapped the keys of
// output_config.
var (
	anthropicConverseMapped = []string{
		"model", "system", "messages", "max_tokens", "temperature", "top_p", "top_k",
		"stream", "stop_sequences", "tools", "tool_choice", "cache_control", "output_config",
	}
	anthropicOutputConfigMapped = []string{"format"}
)

// AnthropicKeysUnmappedOnConverse lists, sorted, the keys of an Anthropic
// Messages body that have no Converse spelling and are left out when it is
// translated: top-level keys by name, output_config keys as
// "output_config.<key>".
func AnthropicKeysUnmappedOnConverse(body []byte) []string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	var out []string
	for key := range raw {
		if !slices.Contains(anthropicConverseMapped, key) {
			out = append(out, key)
		}
	}
	var oc map[string]json.RawMessage
	if json.Unmarshal(raw["output_config"], &oc) == nil {
		for key := range oc {
			if !slices.Contains(anthropicOutputConfigMapped, key) {
				out = append(out, "output_config."+key)
			}
		}
	}
	slices.Sort(out)
	return out
}
