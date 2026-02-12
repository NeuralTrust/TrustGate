package adapter

import "fmt"

// AdaptRequest transforms a request body from source format to target format
// via the canonical internal model: source.Decode → canonical → target.Encode.
//
// If the two formats are wire-compatible the body is returned unmodified.
func AdaptRequest(body []byte, source, target Format) ([]byte, error) {
	if IsSameWireFormat(source, target) {
		return body, nil
	}

	srcAdapter, err := getAdapter(source)
	if err != nil {
		return nil, fmt.Errorf("adapter request: %w", err)
	}
	dstAdapter, err := getAdapter(target)
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
