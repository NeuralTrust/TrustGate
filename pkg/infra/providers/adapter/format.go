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
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
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

// VertexModelsRouteSegment precedes the model in a native Vertex path such as
// "/v1/projects/p/locations/r/publishers/google/models/gemini-pro:generateContent".
const VertexModelsRouteSegment = "/publishers/google/models/"

// GeminiModelFromPath extracts the model segment of a Gemini or Vertex
// generateContent path, e.g. "/v1beta/models/gemini-pro:generateContent" ->
// "gemini-pro".
func GeminiModelFromPath(path string) string {
	marker := GeminiModelsRoutePrefix
	idx := strings.Index(path, marker)
	if idx < 0 {
		marker = VertexModelsRouteSegment
		idx = strings.Index(path, marker)
	}
	if idx < 0 {
		return ""
	}
	model, _ := SplitGeminiModelAction(path[idx+len(marker):])
	return model
}

// geminiMethods are the methods TrustGate routes on a Gemini or Vertex model
// path. Any other suffix after a ':' is part of the model id.
var geminiMethods = map[string]struct{}{
	"generateContent":       {},
	"streamGenerateContent": {},
	"countTokens":           {},
	"embedContent":          {},
	"batchEmbedContents":    {},
	"predict":               {},
	"streamRawPredict":      {},
	"rawPredict":            {},
}

// SplitGeminiModelAction splits the last segment of a Gemini model path into
// the model and its method. The split is at the last ':' followed by one of
// the methods TrustGate routes (geminiMethods), because model ids can contain
// ':' themselves (Bedrock "eu.amazon.nova-lite-v1:0"). A segment without such
// a method, an unknown one such as batchGenerateContent included, is all
// model. The segment is not percent-decoded: no SDK encodes the ':', and
// decoding here alone would let the stream detection, which reads the raw
// path, disagree with routing, and would let %3F or %23 into model ids.
func SplitGeminiModelAction(segment string) (model, action string) {
	if c := strings.LastIndexByte(segment, ':'); c >= 0 {
		if _, ok := geminiMethods[segment[c+1:]]; ok {
			return segment[:c], segment[c+1:]
		}
	}
	return segment, ""
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

// IsChatRequest reports whether a request of the proxy capability, sent in
// wire format f, is a chat request, the only kind that declares tools. The
// capability decides when set; a caller that does not route by capability
// leaves it to the format.
func IsChatRequest(capability string, f Format) bool {
	if capability != "" {
		return capability == providers.CapabilityChat || capability == providers.CapabilityBedrockNative
	}
	switch f {
	case FormatOpenAIEmbeddings, FormatOpenAIFiles, FormatOpenAIImages, FormatOpenAIAudio,
		FormatCohereEmbed, FormatCohereRerank, FormatVertexEmbed, FormatBedrockTitanEmbed:
		return false
	default:
		return true
	}
}

func SupportedSourceFormat(f Format) bool {
	switch f {
	case FormatOpenAI, FormatOpenAIResponses, FormatAnthropic, FormatGemini, FormatBedrock, FormatBedrockNative,
		FormatAzure, FormatGroq, FormatVertex, FormatMistral, FormatDeepSeek, FormatXAI, FormatOpenRouter,
		FormatCohere, FormatOpenAIEmbeddings, FormatOpenAIFiles, FormatOpenAIImages, FormatOpenAIAudio,
		FormatCohereEmbed, FormatCohereRerank,
		FormatVertexEmbed, FormatBedrockTitanEmbed:
		return true
	default:
		return false
	}
}

// geminiStreamAction is the Gemini/Vertex URL action that signals a streamed
// response (clients hit ".../models/<model>:streamGenerateContent"). The leading
// colon is part of the match so unrelated paths that merely contain the word
// "streamGenerateContent" do not trigger a false positive.
const geminiStreamAction = ":streamGenerateContent"

// URLRequestsStream reports whether the request URL asks for a streamed
// response, the way Gemini and Vertex signal it: the ":streamGenerateContent"
// action in the path or "alt=sse" in the query. Their bodies carry no stream
// flag, so a decoded Gemini request always reads as buffered; anything that
// decides on the stream flag must consult the URL as well.
func URLRequestsStream(path string, query url.Values) bool {
	if strings.Contains(path, geminiStreamAction) {
		return true
	}
	return query != nil && query.Get("alt") == "sse"
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

// prefersMaxCompletionTokens reports whether the provider's Chat Completions
// surface takes max_completion_tokens instead of max_tokens; Azure requires
// api-version 2024-10-21 or 2024-09-01-preview and later.
func prefersMaxCompletionTokens(providerName string) bool {
	switch providerName {
	case provider.OpenAI, provider.Azure:
		return true
	}
	return false
}

func ResolveTargetFormat(providerName string, providerOptions map[string]any) Format {
	f := resolveProviderWireFormat(providerName)
	providerFormat := Format(providerName)

	if providerFormat == FormatOpenAI || providerFormat == FormatAzure {
		if api, ok := providerOptions["api"]; ok {
			if s, ok := api.(string); ok {
				switch s {
				case providers.OpenAIAPIResponses:
					return FormatOpenAIResponses
				case providers.AzureAPIAnthropic:
					return FormatAnthropic
				}
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
	case provider.OpenAI, provider.OpenAICompatible, provider.Azure, provider.Groq, provider.DeepSeek, provider.XAI, provider.Cerebras, provider.Moonshot, provider.OpenRouter:
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
// adds. An explicit provider_options.api still wins. Azure registries select
// their Foundry wire format explicitly because the resource endpoint alone
// does not identify the deployed model protocol.
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
		case providers.AzureAPIAnthropic:
			return FormatAnthropic
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
	out := make(map[string]any)
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
