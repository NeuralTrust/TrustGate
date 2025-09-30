package httpx

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
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

func gzipCompress(data []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(data)
	_ = gz.Close()
	return buf.Bytes()
}

func brCompress(data []byte) []byte {
	var buf bytes.Buffer
	br := brotli.NewWriter(&buf)
	_, _ = br.Write(data)
	_ = br.Close()
	return buf.Bytes()
}

func zstdCompress(data []byte) []byte {
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func zlibDeflateCompress(data []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func rawDeflateCompress(data []byte) []byte {
	var buf bytes.Buffer
	dw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = dw.Write(data)
	_ = dw.Close()
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
	comp := gzipCompress(plain)
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
	comp := brCompress(plain)
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
	comp := zstdCompress(plain)
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
	comp := zlibDeflateCompress(plain)
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
	comp := rawDeflateCompress(plain)
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
	gz := gzipCompress(plain)
	br := brCompress(gz)
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
	comp := gzipCompress(plain)
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
func TestHelpers_CompressRoundTrip(t *testing.T) {
	plain := []byte("roundtrip")
	if out, _ := io.ReadAll(mustGzipReader(gzipCompress(plain))); !bytes.Equal(out, plain) {
		t.Fatalf("gzip roundtrip failed")
	}
}

func mustGzipReader(b []byte) io.Reader {
	gr, _ := gzip.NewReader(bytes.NewReader(b))
	return gr
}
