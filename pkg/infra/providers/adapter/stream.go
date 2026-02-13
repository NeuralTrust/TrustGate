package adapter

import "fmt"

// SSEEvent builds the standard SSE lines for one event:
//
//	event: <eventType>
//	data: <dataJSON>
//	<empty line>
//
// The caller writes each element followed by "\n".
func SSEEvent(eventType string, dataJSON []byte) [][]byte {
	return [][]byte{
		[]byte("event: " + eventType),
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}

// SSEData builds a single "data: …" line followed by an empty separator.
// This is the format used by providers that do not emit "event:" lines
// (e.g. OpenAI, Azure).
func SSEData(dataJSON []byte) [][]byte {
	return [][]byte{
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}

// DecodeStreamChunkFor decodes a single SSE data payload from the given
// provider format into a canonical stream chunk. Used by the handler when
// it needs to accumulate (e.g. tool call arguments) before encoding to source.
func DecodeStreamChunkFor(chunk []byte, target Format) (*CanonicalStreamChunk, error) {
	ad, err := getAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	return ad.DecodeStreamChunk(chunk)
}

// EncodeStreamChunkFor encodes a canonical stream chunk into the given
// provider's SSE format. Used by the handler after accumulation (e.g. when
// target is Gemini and tool calls were merged from upstream OpenAI deltas).
func EncodeStreamChunkFor(canonical *CanonicalStreamChunk, source Format) ([][]byte, error) {
	if canonical == nil {
		return nil, nil
	}
	ad, err := getAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	return ad.EncodeStreamChunk(canonical)
}

// AdaptStreamChunk transforms a single SSE data payload from the target
// provider format to the source (caller) format via the canonical model.
//
// Returns (nil, nil) when the chunk should be skipped (e.g. Anthropic ping).
// Each element in the returned slice is a raw SSE line to be written + "\n".
func AdaptStreamChunk(chunk []byte, source, target Format) ([][]byte, error) {
	if IsSameWireFormat(source, target) {
		// Same wire format — wrap the payload in "data: " so the handler
		// can write it directly.
		return SSEData(chunk), nil
	}

	targetAdapter, err := getAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}
	sourceAdapter, err := getAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter stream: %w", err)
	}

	canonical, err := targetAdapter.DecodeStreamChunk(chunk)
	if err != nil {
		return nil, fmt.Errorf("adapter stream decode (%s): %w", target, err)
	}
	if canonical == nil {
		return nil, nil // skip this chunk
	}

	out, err := sourceAdapter.EncodeStreamChunk(canonical)
	if err != nil {
		return nil, fmt.Errorf("adapter stream encode (%s): %w", source, err)
	}

	return out, nil
}
