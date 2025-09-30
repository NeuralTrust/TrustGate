package httpx

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/valyala/fasthttp"
)

// DecodeChain decodes an HTTP response body according to the Content-Encoding header.
// Supports chained encodings (e.g., "gzip, br") and the following algorithms: br, gzip, zstd, deflate.
// For deflate, both zlib-wrapped and raw deflate are handled.
// Returns the decoded body, whether it changed, and an error if decoding failed.
func DecodeChain(resp *fasthttp.Response, body []byte) ([]byte, bool, error) {
	ce := string(resp.Header.Peek("Content-Encoding"))
	if ce == "" {
		return body, false, nil
	}
	compressions := strings.Split(ce, ",")
	changed := false
	for i := len(compressions) - 1; i >= 0; i-- {
		switch strings.TrimSpace(strings.ToLower(compressions[i])) {
		case "br":
			r := brotli.NewReader(bytes.NewReader(body))
			var err error
			body, err = io.ReadAll(r)
			if err != nil {
				return nil, false, err
			}
			changed = true
		case "gzip":
			gr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, false, err
			}
			out, err := io.ReadAll(gr)
			cerr := gr.Close()
			if err != nil {
				return nil, false, err
			}
			if cerr != nil {
				return nil, false, cerr
			}
			body = out
			changed = true
		case "zstd":
			dec, err := zstd.NewReader(bytes.NewReader(body))
			if err != nil {
				return nil, false, err
			}
			out, err := io.ReadAll(dec)
			dec.Close()
			if err != nil {
				return nil, false, err
			}
			body = out
			changed = true
		case "deflate":
			// Try zlib-wrapped first (RFC)
			zr, err := zlib.NewReader(bytes.NewReader(body))
			if err == nil {
				out, err2 := io.ReadAll(zr)
				cerr := zr.Close()
				if err2 != nil {
					return nil, false, err2
				}
				if cerr != nil {
					return nil, false, cerr
				}
				body = out
				changed = true
				break
			}
			// Fallback to raw DEFLATE
			fr := flate.NewReader(bytes.NewReader(body))
			out, err2 := io.ReadAll(fr)
			cerr := fr.Close()
			if err2 != nil {
				return nil, false, err2
			}
			if cerr != nil {
				return nil, false, cerr
			}
			body = out
			changed = true
		case "compress", "identity":
			// No action
		case "":
			// Skip empty segment
		default:
			return nil, false, fmt.Errorf("unsupported content-encoding: %q", compressions[i])
		}
	}
	return body, changed, nil
}
