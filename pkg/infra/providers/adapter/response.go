package adapter

import "fmt"

// DecodeResponseFor decodes a raw provider response into the canonical model.
// It is the response counterpart of DecodeStreamChunkFor.
func DecodeResponseFor(body []byte, providerFormat Format) (*CanonicalResponse, error) {
	a, err := getAdapter(providerFormat)
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
func AdaptResponse(body []byte, source, target Format) ([]byte, error) {
	if IsSameWireFormat(source, target) {
		return body, nil
	}

	// The response was produced by the target provider; decode with target.
	targetAdapter, err := getAdapter(target)
	if err != nil {
		return nil, fmt.Errorf("adapter response: %w", err)
	}
	// The caller expects the source format; encode with source.
	sourceAdapter, err := getAdapter(source)
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
