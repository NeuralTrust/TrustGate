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

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
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
	FormatDeepSeek        Format = "deepseek" // wire-compatible with OpenAI Chat Completions
	FormatXAI             Format = "xai"      // wire-compatible with OpenAI Chat Completions
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

// SupportsCanonicalToolCalls reports whether a response in this wire format can
// carry tool calls the gateway knows how to translate into the caller's format.
func (f Format) SupportsCanonicalToolCalls() bool {
	return IsSameWireFormat(f, FormatOpenAI) ||
		f == FormatOpenAIResponses ||
		f == FormatAnthropic ||
		f == FormatMistral
}

// IsOpenAIFamily reports whether the format speaks an OpenAI-compatible wire
// protocol: Chat Completions (openai, azure, groq, deepseek) or the Responses API.
func (f Format) IsOpenAIFamily() bool {
	return f == FormatOpenAIResponses || IsSameWireFormat(f, FormatOpenAI)
}

func SupportedSourceFormat(f Format) bool {
	switch f {
	case FormatOpenAI, FormatOpenAIResponses, FormatAnthropic, FormatGemini,
		FormatAzure, FormatGroq, FormatVertex, FormatMistral, FormatDeepSeek, FormatXAI:
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

func resolveProviderWireFormat(providerName string) Format {
	switch providerName {
	case provider.Groq:
		return FormatGroq
	case provider.DeepSeek:
		return FormatDeepSeek
	case provider.XAI:
		return FormatXAI
	case provider.OpenAICompatible:
		return FormatOpenAI
	default:
		return Format(providerName)
	}
}

func ResolveTargetFormat(providerName string, providerOptions map[string]any) Format {
	f := resolveProviderWireFormat(providerName)
	providerFormat := Format(providerName)

	if providerFormat == FormatOpenAI || providerFormat == FormatAzure {
		if api, ok := providerOptions["api"]; ok {
			if s, ok := api.(string); ok && s == "responses" {
				return FormatOpenAIResponses
			}
		}
	}

	return f
}

func ResolveAgentFormat(providerName, sourceFormat string, providerOptions map[string]any) (Format, error) {
	if sourceFormat != "" {
		return Format(sourceFormat), nil
	}
	switch providerName {
	case provider.OpenAI, provider.OpenAICompatible, provider.Azure, provider.Groq, provider.DeepSeek, provider.XAI:
		return ResolveTargetFormat(providerName, providerOptions), nil
	case provider.Anthropic:
		return FormatAnthropic, nil
	case provider.Google:
		return FormatGemini, nil
	case provider.Bedrock:
		return FormatBedrock, nil
	case provider.Mistral:
		return FormatMistral, nil
	case provider.Vertex:
		return FormatVertex, nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", providerName)
	}
}

func IsSameWireFormat(a, b Format) bool {
	na := normalizeFormat(a)
	nb := normalizeFormat(b)
	return na == nb
}

func normalizeFormat(f Format) Format {
	switch f {
	case FormatAzure, FormatGroq, FormatDeepSeek, FormatXAI:
		return FormatOpenAI
	case FormatVertex:
		return FormatGemini
	default:
		return f
	}
}
