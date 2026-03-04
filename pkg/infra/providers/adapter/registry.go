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
//
// EncodeStreamChunk returns a slice of raw SSE lines. Each element is written
// followed by "\n" by the handler. Typical elements include "event: …",
// "data: {…}" and "" (empty-line event separator). This allows providers that
// require multi-line SSE events (e.g. Anthropic's event: + data:) to produce
// a byte-accurate stream.
type StreamAdapter interface {
	DecodeStreamChunk(chunk []byte) (*CanonicalStreamChunk, error)
	EncodeStreamChunk(chunk *CanonicalStreamChunk) ([][]byte, error)
}

// ProviderAdapter combines all three conversion interfaces.
type ProviderAdapter interface {
	RequestAdapter
	ResponseAdapter
	StreamAdapter
}

// Registry holds provider adapters and exposes methods for cross-provider
// format adaptation. Unlike a global map+init(), a Registry is explicitly
// constructed and injected, making it testable and configurable.
type Registry struct {
	adapters map[Format]ProviderAdapter
}

// NewRegistry creates a Registry pre-populated with all built-in adapters.
func NewRegistry() *Registry {
	r := &Registry{
		adapters: make(map[Format]ProviderAdapter),
	}
	r.Register(FormatOpenAI, &OpenAIAdapter{})
	r.Register(FormatOpenAIResponses, &OpenAIResponsesAdapter{})
	r.Register(FormatAnthropic, &AnthropicAdapter{})
	r.Register(FormatGemini, &GeminiAdapter{})
	r.Register(FormatBedrock, &BedrockAdapter{})
	r.Register(FormatMistral, &MistralAdapter{})
	return r
}

// Register adds or replaces an adapter for the given format.
func (r *Registry) Register(f Format, a ProviderAdapter) {
	r.adapters[f] = a
}

// GetAdapter returns the adapter for a format, resolving aliases.
func (r *Registry) GetAdapter(f Format) (ProviderAdapter, error) {
	f = normalizeFormat(f)
	a, ok := r.adapters[f]
	if !ok {
		return nil, fmt.Errorf("adapter: no adapter registered for format %q", f)
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// Request adaptation
// ---------------------------------------------------------------------------

// DecodeRequestFor decodes a raw provider request into the canonical model.
func (r *Registry) DecodeRequestFor(body []byte, providerFormat Format) (*CanonicalRequest, error) {
	a, err := r.GetAdapter(providerFormat)
	if err != nil {
		return nil, fmt.Errorf("adapter request: %w", err)
	}
	return a.DecodeRequest(body)
}

// AdaptRequest transforms a request body from source format to target format
// via the canonical internal model: source.Decode → canonical → target.Encode.
//
// If the two formats are wire-compatible the body is returned unmodified.
func (r *Registry) AdaptRequest(body []byte, source, target Format) ([]byte, error) {
	if IsSameWireFormat(source, target) {
		return body, nil
	}

	srcAdapter, err := r.GetAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter request: %w", err)
	}
	dstAdapter, err := r.GetAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter request: %w", err)
	}

	canonical, err := srcAdapter.DecodeRequest(body)
	if err != nil {
		return nil, fmt.Errorf("adapter request decode (%s): %w", source, err)
	}

	out, err := dstAdapter.EncodeRequest(canonical)
	if err != nil {
		return nil, fmt.Errorf("adapter request encode (%s): %w", target, err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Response adaptation
// ---------------------------------------------------------------------------

// DecodeResponseFor decodes a raw provider response into the canonical model.
func (r *Registry) DecodeResponseFor(body []byte, providerFormat Format) (*CanonicalResponse, error) {
	a, err := r.GetAdapter(providerFormat)
	if err != nil {
		return nil, fmt.Errorf("adapter response: %w", err)
	}
	return a.DecodeResponse(body)
}

// AdaptResponse transforms a provider response from targetFormat back to
// sourceFormat via the canonical model: target.DecodeResponse → canonical →
// source.EncodeResponse.
//
// If the two formats are wire-compatible the body is returned unmodified.
func (r *Registry) AdaptResponse(body []byte, source, target Format) ([]byte, error) {
	if IsSameWireFormat(source, target) {
		return body, nil
	}

	targetAdapter, err := r.GetAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter response: %w", err)
	}
	sourceAdapter, err := r.GetAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter response: %w", err)
	}

	canonical, err := targetAdapter.DecodeResponse(body)
	if err != nil {
		return nil, fmt.Errorf("adapter response decode (%s): %w", target, err)
	}

	out, err := sourceAdapter.EncodeResponse(canonical)
	if err != nil {
		return nil, fmt.Errorf("adapter response encode (%s): %w", source, err)
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Stream chunk adaptation
// ---------------------------------------------------------------------------

// DecodeStreamChunkFor decodes a single SSE data payload from the given
// provider format into a canonical stream chunk.
func (r *Registry) DecodeStreamChunkFor(chunk []byte, target Format) (*CanonicalStreamChunk, error) {
	ad, err := r.GetAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	return ad.DecodeStreamChunk(chunk)
}

// EncodeStreamChunkFor encodes a canonical stream chunk into the given
// provider's SSE format.
func (r *Registry) EncodeStreamChunkFor(canonical *CanonicalStreamChunk, source Format) ([][]byte, error) {
	if canonical == nil {
		return nil, nil
	}
	ad, err := r.GetAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	return ad.EncodeStreamChunk(canonical)
}

// AdaptStreamChunk transforms a single SSE data payload from the target
// provider format to the source (caller) format via the canonical model.
//
// Returns (nil, nil) when the chunk should be skipped (e.g. Anthropic ping).
func (r *Registry) AdaptStreamChunk(chunk []byte, source, target Format) ([][]byte, error) {
	if IsSameWireFormat(source, target) {
		return SSEData(chunk), nil
	}

	targetAdapter, err := r.GetAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	sourceAdapter, err := r.GetAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}

	canonical, err := targetAdapter.DecodeStreamChunk(chunk)
	if err != nil {
		return nil, fmt.Errorf("adapter stream decode (%s): %w", target, err)
	}
	if canonical == nil {
		return nil, nil
	}

	out, err := sourceAdapter.EncodeStreamChunk(canonical)
	if err != nil {
		return nil, fmt.Errorf("adapter stream encode (%s): %w", source, err)
	}

	return out, nil
}
