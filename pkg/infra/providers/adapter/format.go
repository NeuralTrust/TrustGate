package adapter

import "encoding/json"

// Format represents an AI provider's API format.
type Format string

const (
	FormatOpenAI    Format = "openai"
	FormatAnthropic Format = "anthropic"
	FormatGemini    Format = "google"
	FormatBedrock   Format = "bedrock"
	FormatAzure     Format = "azure" // wire-compatible with OpenAI
	FormatMistral   Format = "mistral"
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
		// Make sure "system" is a string (not an object/array) to avoid
		// false positives.
		var s string
		if json.Unmarshal(probe.System, &s) == nil {
			return FormatAnthropic
		}
	}

	// 4. Bedrock Titan uses "inputText".
	if probe.InputText != nil {
		return FormatBedrock
	}

	// 5. Bedrock legacy Claude v2 uses "prompt" without "messages".
	if probe.Prompt != nil && probe.Messages == nil {
		return FormatBedrock
	}

	// 6. Default: OpenAI chat-completion format.
	return FormatOpenAI
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
