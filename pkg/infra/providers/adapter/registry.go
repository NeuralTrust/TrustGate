package adapter

import "fmt"

// RequestAdapter converts between a provider's native request format and the
// canonical internal model.
type RequestAdapter interface {
	DecodeRequest(body []byte) (*CanonicalRequest, error)
	EncodeRequest(req *CanonicalRequest) ([]byte, error)
}

// ResponseAdapter converts between a provider's native response format and the
// canonical internal model.
type ResponseAdapter interface {
	DecodeResponse(body []byte) (*CanonicalResponse, error)
	EncodeResponse(resp *CanonicalResponse) ([]byte, error)
}

// StreamAdapter converts between a provider's native SSE chunk format and the
// canonical internal model.
type StreamAdapter interface {
	DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error)
	EncodeStreamChunk(chunk *CanonicalStreamChunk) ([]byte, error)
}

// ProviderAdapter combines all three conversion interfaces.
type ProviderAdapter interface {
	RequestAdapter
	ResponseAdapter
	StreamAdapter
}

// adapters is the global registry of provider adapters.
var adapters = map[Format]ProviderAdapter{}

func init() {
	adapters[FormatOpenAI] = &OpenAIAdapter{}
	adapters[FormatAnthropic] = &AnthropicAdapter{}
	adapters[FormatGemini] = &GeminiAdapter{}
	adapters[FormatBedrock] = &BedrockAdapter{}
	// Azure uses the same wire format as OpenAI — see normalizeFormat().
}

// getAdapter returns the adapter for a format, resolving aliases.
func getAdapter(f Format) (ProviderAdapter, error) {
	f = normalizeFormat(f)
	a, ok := adapters[f]
	if !ok {
		return nil, fmt.Errorf("adapter: no adapter registered for format %q", f)
	}
	return a, nil
}
