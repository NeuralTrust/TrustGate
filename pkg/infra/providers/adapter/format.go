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
	"strings"
)

type Format string

const (
	FormatOpenAI          Format = "openai"
	FormatOpenAIResponses Format = "openai_responses"
	FormatAnthropic       Format = "anthropic"
	FormatGemini          Format = "google"
	FormatBedrock         Format = "bedrock"
	FormatAzure           Format = "azure" // wire-compatible with OpenAI
	FormatGroq            Format = "groq"  // wire-compatible with OpenAI Chat Completions
	FormatVertex          Format = "vertex"
	FormatMistral         Format = "mistral"
)

// GeminiModelsRoutePrefix is the fixed Gemini route segment that carries the
// model in the URL instead of the body.
const GeminiModelsRoutePrefix = "/v1beta/models/"

// GeminiModelFromPath extracts the model segment of a Gemini generateContent
// path, e.g. "/v1beta/models/gemini-pro:generateContent" -> "gemini-pro".
func GeminiModelFromPath(path string) string {
	idx := strings.Index(path, GeminiModelsRoutePrefix)
	if idx < 0 {
		return ""
	}
	model := path[idx+len(GeminiModelsRoutePrefix):]
	if c := strings.IndexByte(model, ':'); c >= 0 {
		model = model[:c]
	}
	return model
}

func DetectFormat(body []byte) Format {
	var probe struct {
		Contents         json.RawMessage `json:"contents"`
		AnthropicVersion json.RawMessage `json:"anthropic_version"`
		System           json.RawMessage `json:"system"`
		Messages         json.RawMessage `json:"messages"`
		Input            json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return FormatOpenAI // safe default
	}

	if probe.Contents != nil {
		return FormatGemini
	}

	if probe.AnthropicVersion != nil {
		return FormatAnthropic
	}

	if probe.System != nil && probe.Messages != nil {
		var s string
		if json.Unmarshal(probe.System, &s) == nil {
			return FormatAnthropic
		}
		var arr []json.RawMessage
		if json.Unmarshal(probe.System, &arr) == nil && len(arr) > 0 {
			return FormatAnthropic
		}
	}

	if probe.Input != nil && probe.Messages == nil {
		return FormatOpenAIResponses
	}

	return FormatOpenAI
}

func SupportedSourceFormat(f Format) bool {
	switch f {
	case FormatOpenAI, FormatOpenAIResponses, FormatAnthropic, FormatGemini,
		FormatAzure, FormatGroq, FormatVertex, FormatMistral:
		return true
	default:
		return false
	}
}

func RequestWantsStream(body []byte) (stream bool, explicit bool) {
	var probe struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || probe.Stream == nil {
		return false, false
	}
	return *probe.Stream, true
}

func resolveProviderWireFormat(provider string) Format {
	switch provider {
	case string(FormatGroq):
		return FormatGroq
	case "openai_compatible":
		return FormatOpenAI
	default:
		return Format(provider)
	}
}

func ResolveTargetFormat(provider string, providerOptions map[string]any) Format {
	f := resolveProviderWireFormat(provider)
	providerFormat := Format(provider)

	if providerFormat == FormatOpenAI || providerFormat == FormatAzure {
		if api, ok := providerOptions["api"]; ok {
			if s, ok := api.(string); ok && s == "responses" {
				return FormatOpenAIResponses
			}
		}
	}

	return f
}

func ResolveAgentFormat(provider, sourceFormat string, providerOptions map[string]any) (Format, error) {
	if sourceFormat != "" {
		return Format(sourceFormat), nil
	}
	switch provider {
	case "openai", "openai_compatible", "azure", "groq":
		return ResolveTargetFormat(provider, providerOptions), nil
	case "anthropic":
		return FormatAnthropic, nil
	case "google":
		return FormatGemini, nil
	case "bedrock":
		return FormatBedrock, nil
	case "mistral":
		return FormatMistral, nil
	case "vertex":
		return FormatVertex, nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func IsSameWireFormat(a, b Format) bool {
	na := normalizeFormat(a)
	nb := normalizeFormat(b)
	return na == nb
}

func normalizeFormat(f Format) Format {
	switch f {
	case FormatAzure, FormatGroq:
		return FormatOpenAI
	case FormatVertex:
		return FormatGemini
	default:
		return f
	}
}
