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
	FormatOpenAI            Format = "openai"
	FormatOpenAIResponses   Format = "openai_responses"
	FormatAnthropic         Format = "anthropic"
	FormatGemini            Format = "google"
	FormatBedrock           Format = "bedrock"
	FormatAzure             Format = "azure" // wire-compatible with OpenAI
	FormatGroq              Format = "groq"  // wire-compatible with OpenAI Chat Completions
	FormatVertex            Format = "vertex"
	FormatMistral           Format = "mistral"
	FormatDeepSeek          Format = "deepseek"   // wire-compatible with OpenAI Chat Completions
	FormatXAI               Format = "xai"        // wire-compatible with OpenAI Chat Completions
	FormatOpenRouter        Format = "openrouter" // wire-compatible with OpenAI Chat Completions
	FormatCohere            Format = "cohere"
	FormatOpenAIEmbeddings  Format = "openai_embeddings"
	FormatOpenAIFiles       Format = "openai_files"
	FormatOpenAIImages      Format = "openai_images"
	FormatOpenAIAudio       Format = "openai_audio"
	FormatCohereEmbed       Format = "cohere_embed"
	FormatCohereRerank      Format = "cohere_rerank"
	FormatVertexEmbed       Format = "vertex_embed"
	FormatBedrockTitanEmbed Format = "bedrock_titan_embed"
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
		f == FormatMistral ||
		f == FormatCohere
}

// IsOpenAIFamily reports whether the format speaks an OpenAI-compatible wire
// protocol: Chat Completions (openai, azure, groq, deepseek) or the Responses API.
func (f Format) IsOpenAIFamily() bool {
	return f == FormatOpenAIResponses || IsSameWireFormat(f, FormatOpenAI)
}

func SupportedSourceFormat(f Format) bool {
	switch f {
	case FormatOpenAI, FormatOpenAIResponses, FormatAnthropic, FormatGemini,
		FormatAzure, FormatGroq, FormatVertex, FormatMistral, FormatDeepSeek, FormatXAI, FormatOpenRouter,
		FormatCohere, FormatOpenAIEmbeddings, FormatOpenAIFiles, FormatOpenAIImages, FormatOpenAIAudio,
		FormatCohereEmbed, FormatCohereRerank,
		FormatVertexEmbed, FormatBedrockTitanEmbed:
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
	case provider.Cerebras:
		return FormatOpenAI
	case provider.Moonshot:
		return FormatOpenAI
	case provider.Together:
		return FormatOpenAI
	case provider.DeepInfra:
		return FormatOpenAI
	case provider.Novita:
		return FormatOpenAI
	case provider.Nebius:
		return FormatOpenAI
	case provider.SiliconFlow:
		return FormatOpenAI
	case provider.SambaNova:
		return FormatOpenAI
	case provider.Fireworks:
		return FormatOpenAI
	case provider.ZAI:
		return FormatOpenAI
	case provider.DashScope:
		return FormatOpenAI
	case provider.Nvidia:
		return FormatOpenAI
	case provider.MiniMax:
		return FormatOpenAI
	case provider.OpenRouter:
		return FormatOpenRouter
	case provider.Cohere:
		return FormatCohere
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
	case provider.OpenAI, provider.OpenAICompatible, provider.Azure, provider.Groq, provider.DeepSeek, provider.XAI, provider.Cerebras, provider.Moonshot, provider.Together, provider.DeepInfra, provider.Novita, provider.Nebius, provider.SiliconFlow, provider.SambaNova, provider.Fireworks, provider.ZAI, provider.DashScope, provider.Nvidia, provider.MiniMax, provider.OpenRouter:
		return ResolveTargetFormat(providerName, providerOptions), nil
	case provider.Anthropic:
		return FormatAnthropic, nil
	case provider.Google:
		return FormatGemini, nil
	case provider.Bedrock:
		return FormatBedrock, nil
	case provider.Mistral:
		return FormatMistral, nil
	case provider.Cohere:
		return FormatCohere, nil
	case provider.Vertex:
		return FormatVertex, nil
	default:
		return "", fmt.Errorf("unsupported provider: %s", providerName)
	}
}

// ResolveTargetFormatForCapability picks the provider wire format for a proxy capability.
// sourceFormat is the dialect the client spoke, derived from the inbound route.
func ResolveTargetFormatForCapability(
	providerName string,
	capability string,
	sourceFormat Format,
	providerOptions map[string]any,
) Format {
	switch capability {
	case "embeddings":
		switch providerName {
		case provider.Cohere:
			return FormatCohereEmbed
		case provider.Vertex:
			return FormatVertexEmbed
		case provider.Bedrock:
			return FormatBedrockTitanEmbed
		default:
			return FormatOpenAIEmbeddings
		}
	case "rerank":
		return FormatCohereRerank
	case "files":
		return FormatOpenAIFiles
	case "images":
		return FormatOpenAIImages
	case "audio_speech", "audio_transcription":
		return FormatOpenAIAudio
	default:
		return resolveChatTargetFormat(providerName, sourceFormat, providerOptions)
	}
}

// Values accepted by provider_options.api for the OpenAI provider. Duplicated
// from pkg/infra/providers to keep this package free of that dependency.
const (
	OpenAIAPICompletions = "completions"
	OpenAIAPIResponses   = "responses"
)

// OpenAI exposes two chat surfaces, and a client picks one by calling either
// /v1/chat/completions or /v1/responses. Honour that choice: downgrading a
// Responses request to Chat Completions drops everything the newer surface
// adds. An explicit provider_options.api still wins, which is the only way to
// reach a surface the client did not ask for. Azure is excluded from the
// mirroring because its client only builds chat/completions URLs.
func resolveChatTargetFormat(providerName string, sourceFormat Format, providerOptions map[string]any) Format {
	wireFormat := resolveProviderWireFormat(providerName)
	providerFormat := Format(providerName)
	if providerFormat != FormatOpenAI && providerFormat != FormatAzure {
		return wireFormat
	}
	if api, ok := providerOptions["api"].(string); ok {
		switch api {
		case OpenAIAPIResponses:
			return FormatOpenAIResponses
		case OpenAIAPICompletions:
			return wireFormat
		}
	}
	if providerFormat == FormatOpenAI && sourceFormat == FormatOpenAIResponses {
		return FormatOpenAIResponses
	}
	return wireFormat
}

// OpenAIProviderOptionsForTarget restates the resolved chat surface in the
// options handed to the provider client, which picks its endpoint from
// provider_options.api. Without this the route-derived decision and the URL the
// client builds could disagree. The input map is never mutated.
func OpenAIProviderOptionsForTarget(providerName string, targetFormat Format, options map[string]any) map[string]any {
	if Format(providerName) != FormatOpenAI {
		return options
	}
	api := OpenAIAPICompletions
	if targetFormat == FormatOpenAIResponses {
		api = OpenAIAPIResponses
	}
	if current, ok := options["api"].(string); ok && current == api {
		return options
	}
	out := make(map[string]any, len(options)+1)
	for k, v := range options {
		out[k] = v
	}
	out["api"] = api
	return out
}

func IsSameWireFormat(a, b Format) bool {
	na := normalizeFormat(a)
	nb := normalizeFormat(b)
	return na == nb
}

func normalizeFormat(f Format) Format {
	switch f {
	case FormatAzure, FormatGroq, FormatDeepSeek, FormatXAI, FormatOpenRouter:
		return FormatOpenAI
	case FormatVertex:
		return FormatGemini
	default:
		return f
	}
}
