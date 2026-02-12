package adapter

import "fmt"

// AdaptStreamChunk transforms a single SSE data payload from the target
// provider format to the source (caller) format via the canonical model.
//
// Returns (nil, nil) when the chunk should be skipped (e.g. Anthropic ping).
func AdaptStreamChunk(chunk []byte, source, target Format) ([]byte, error) {
	if IsSameWireFormat(source, target) {
		return chunk, nil
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
