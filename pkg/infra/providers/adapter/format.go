package adapter

import (
	"encoding/json"
	"fmt"
)

// Format represents an AI provider's API format.
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

// DetectFormat inspects the raw JSON body and returns the most likely source
// format. The function performs lightweight key probing (no full
// deserialization) so it is safe on arbitrarily large payloads.
//
// Heuristics (evaluated in order):
//  1. Has "contents" key                        → Gemini
//  2. Has "anthropic_version" key               → Anthropic
//  3. Has top-level "system" (string or array) AND "messages" → Anthropic
//  4. Has "input" without "messages"            → OpenAI Responses
//  5. Default (has "messages")                  → OpenAI
//
// Bedrock is intentionally never detected: the gateway only accepts universal
// payloads as input, so provider-native Bedrock bodies (modelId, inputText,
// prompt) are not a supported source format.
func DetectFormat(body []byte) Format {
	// Quick probe: unmarshal into a thin map that only captures keys we care
	// about. Values are kept as json.RawMessage to avoid allocating real
	// objects.
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

	// 1. Gemini native format uses "contents".
	if probe.Contents != nil {
		return FormatGemini
	}

	// 2. Explicit Anthropic version header in body.
	if probe.AnthropicVersion != nil {
		return FormatAnthropic
	}

	// 3. Anthropic uses a top-level "system" alongside "messages".
	// It can be a plain string or an array of content blocks (newer format
	// with cache_control support). OpenAI never has a top-level "system".
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

	// 4. OpenAI Responses API uses "input" without "messages".
	if probe.Input != nil && probe.Messages == nil {
		return FormatOpenAIResponses
	}

	// 5. Default: OpenAI chat-completion format.
	return FormatOpenAI
}

// SupportedSourceFormat reports whether a Format is accepted as the wire
// format of an inbound request body (X-Provider header). Bedrock is excluded:
// clients must send universal payloads, never provider-native Bedrock bodies.
func SupportedSourceFormat(f Format) bool {
	switch f {
	case FormatOpenAI, FormatOpenAIResponses, FormatAnthropic, FormatGemini,
		FormatAzure, FormatGroq, FormatVertex, FormatMistral:
		return true
	default:
		return false
	}
}

// RequestWantsStream reports whether the body carries an explicit "stream" flag
// (the OpenAI/Anthropic/Mistral/Responses wire convention). explicit is false
// when the key is absent (e.g. Gemini bodies, which signal streaming via URL)
// or when the body is not valid JSON, so callers can fall back to other signals.
func RequestWantsStream(body []byte) (stream bool, explicit bool) {
	var probe struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || probe.Stream == nil {
		return false, false
	}
	return *probe.Stream, true
}

// resolveProviderWireFormat maps a provider identifier to its wire Format.
// Some first-class providers expose OpenAI-compatible APIs and reuse FormatOpenAI.
func resolveProviderWireFormat(provider string) Format {
	switch provider {
	case "groq":
		return FormatGroq
	case "openai_compatible":
		// Generic OpenAI-compatible upstreams speak the OpenAI Chat Completions
		// wire format and reuse the OpenAI adapter.
		return FormatOpenAI
	default:
		return Format(provider)
	}
}

// ResolveTargetFormat returns the effective adapter Format for an upstream
// target by combining its provider name with ProviderOptions. For example,
// provider "openai" with provider_options {"api": "responses"} resolves to
// FormatOpenAIResponses instead of FormatOpenAI.
func ResolveTargetFormat(provider string, providerOptions map[string]any) Format {
	f := resolveProviderWireFormat(provider)
	providerFormat := Format(provider)

	// Only first-class OpenAI and Azure targets can opt into the Responses API.
	// openai_compatible is Chat Completions only, so it is intentionally excluded.
	if providerFormat == FormatOpenAI || providerFormat == FormatAzure {
		if api, ok := providerOptions["api"]; ok {
			if s, ok := api.(string); ok && s == "responses" {
				return FormatOpenAIResponses
			}
		}
	}

	return f
}

// ResolveAgentFormat maps gateway provider identifiers to Format for parser /
// registry selection (plugins, Enterprise). Provider strings must match
// pkg/infra/providers client constants. When sourceFormat is non-empty it
// wins (explicit client wire format). providerOptions is forwarded to
// ResolveTargetFormat for providers that need target-specific format resolution.
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

// IsSameWireFormat returns true when two formats are wire-compatible and
// no request/response transformation is necessary.
func IsSameWireFormat(a, b Format) bool {
	na := normalizeFormat(a)
	nb := normalizeFormat(b)
	return na == nb
}

// normalizeFormat maps aliases to a canonical format.
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
