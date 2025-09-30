package httpx

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/valyala/fasthttp"
)

func makeRespWithCE(enc string) *fasthttp.Response {
	resp := fasthttp.AcquireResponse()
	resp.Header.Set("Content-Encoding", enc)
	return resp
}

func gzipCompress(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatalf("gzip write error: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close error: %v", err)
	}
	return buf.Bytes()
}

func brCompress(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	br := brotli.NewWriter(&buf)
	if _, err := br.Write(data); err != nil {
		t.Fatalf("brotli write error: %v", err)
	}
	if err := br.Close(); err != nil {
		t.Fatalf("brotli close error: %v", err)
	}
	return buf.Bytes()
}

func zstdCompress(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer error: %v", err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zstd write error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close error: %v", err)
	}
	return buf.Bytes()
}

func zlibDeflateCompress(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib write error: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close error: %v", err)
	}
	return buf.Bytes()
}

func rawDeflateCompress(t *testing.T, data []byte) []byte {
	var buf bytes.Buffer
	dw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer error: %v", err)
	}
	if _, err := dw.Write(data); err != nil {
		t.Fatalf("flate write error: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("flate close error: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeChain_NoEncoding(t *testing.T) {
	plain := []byte("hello world")
	resp := fasthttp.AcquireResponse() // no Content-Encoding header
	decoded, changed, err := DecodeChain(resp, plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded body mismatch: got %q want %q", decoded, plain)
	}
}

func TestDecodeChain_Gzip(t *testing.T) {
	plain := []byte("gzip payload")
	comp := gzipCompress(t, plain)
	resp := makeRespWithCE("gzip")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true for gzip")
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded body mismatch")
	}
}

func TestDecodeChain_Brotli(t *testing.T) {
	plain := []byte("brotli payload")
	comp := brCompress(t, plain)
	resp := makeRespWithCE("br")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("brotli decode failed")
	}
}

func TestDecodeChain_Zstd(t *testing.T) {
	plain := []byte("zstd payload")
	comp := zstdCompress(t, plain)
	resp := makeRespWithCE("zstd")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("zstd decode failed")
	}
}

func TestDecodeChain_Deflate_ZlibWrapped(t *testing.T) {
	plain := []byte("deflate zlib wrapped")
	comp := zlibDeflateCompress(t, plain)
	resp := makeRespWithCE("deflate")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("deflate (zlib) decode failed")
	}
}

func TestDecodeChain_Deflate_Raw(t *testing.T) {
	plain := []byte("deflate raw payload")
	comp := rawDeflateCompress(t, plain)
	resp := makeRespWithCE("deflate")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("deflate (raw) decode failed")
	}
}

func TestDecodeChain_Identity_Compress_NoOp(t *testing.T) {
	plain := []byte("no-op encodings")
	resp := makeRespWithCE("identity, compress")
	decoded, changed, err := DecodeChain(resp, plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatalf("expected no change for identity/compress")
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded mismatch for identity/compress")
	}
}

func TestDecodeChain_UnknownEncoding_ReturnsError(t *testing.T) {
	plain := []byte("abc")
	resp := makeRespWithCE("foo")
	_, _, err := DecodeChain(resp, plain)
	if err == nil {
		t.Fatalf("expected error for unknown encoding")
	}
}

func TestDecodeChain_Chained_GzipThenBr(t *testing.T) {
	plain := []byte("chain payload")
	// Apply gzip then br (server would set Content-Encoding: gzip, br)
	gz := gzipCompress(t, plain)
	br := brCompress(t, gz)
	resp := makeRespWithCE("gzip, br")
	decoded, changed, err := DecodeChain(resp, br)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("chained decode failed")
	}
}

func TestDecodeChain_CaseAndWhitespace(t *testing.T) {
	plain := []byte("gzip case payload")
	comp := gzipCompress(t, plain)
	resp := makeRespWithCE("  GZip  ")
	decoded, changed, err := DecodeChain(resp, comp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !bytes.Equal(decoded, plain) {
		t.Fatalf("case-insensitive decode failed")
	}
}

// Ensure helpers work as expected (sanity check)
// Note: helpers are validated implicitly by decode tests above.
