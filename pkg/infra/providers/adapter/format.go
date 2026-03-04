package adapter

import "encoding/json"

// Format represents an AI provider's API format.
type Format string

const (
	FormatOpenAI          Format = "openai"
	FormatOpenAIResponses Format = "openai_responses"
	FormatAnthropic       Format = "anthropic"
	FormatGemini          Format = "google"
	FormatBedrock         Format = "bedrock"
	FormatAzure           Format = "azure" // wire-compatible with OpenAI
	FormatMistral         Format = "mistral"
)

// DetectFormat inspects the raw JSON body and returns the most likely source
// format. The function performs lightweight key probing (no full
// deserialization) so it is safe on arbitrarily large payloads.
//
// Heuristics (evaluated in order):
//  1. Has "contents" key                        → Gemini
//  2. Has "anthropic_version" key               → Anthropic
//  3. Has top-level "system" string AND "messages" → Anthropic
//  4. Has "inputText" key                       → Bedrock (Titan)
//  5. Has "prompt" key without "messages"        → Bedrock (legacy Claude v2)
//  6. Default (has "messages")                  → OpenAI
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
		InputText        json.RawMessage `json:"inputText"`
		Prompt           json.RawMessage `json:"prompt"`
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

	// 3. Anthropic uses a top-level "system" string alongside "messages".
	// OpenAI never has a top-level "system" – system prompts live inside the
	// messages array.
	if probe.System != nil && probe.Messages != nil {
		var s string
		if json.Unmarshal(probe.System, &s) == nil {
			return FormatAnthropic
		}
	}

	// 4. OpenAI Responses API uses "input" without "messages".
	if probe.Input != nil && probe.Messages == nil {
		return FormatOpenAIResponses
	}

	// 5. Bedrock Titan uses "inputText".
	if probe.InputText != nil {
		return FormatBedrock
	}

	// 6. Bedrock legacy Claude v2 uses "prompt" without "messages".
	if probe.Prompt != nil && probe.Messages == nil {
		return FormatBedrock
	}

	// 7. Default: OpenAI chat-completion format.
	return FormatOpenAI
}

// ResolveTargetFormat returns the effective adapter Format for an upstream
// target by combining its Provider name with ProviderOptions. For example,
// provider "openai" with provider_options {"api": "responses"} resolves to
// FormatOpenAIResponses instead of FormatOpenAI.
func ResolveTargetFormat(provider string, providerOptions map[string]any) Format {
	f := Format(provider)
	if f == FormatOpenAI || f == FormatAzure {
		if api, ok := providerOptions["api"]; ok {
			if s, ok := api.(string); ok && s == "responses" {
				return FormatOpenAIResponses
			}
		}
	}
	return f
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
	case FormatAzure:
		return FormatOpenAI
	default:
		return f
	}
}
