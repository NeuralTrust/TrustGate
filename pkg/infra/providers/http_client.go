package providers

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultHTTPTimeout is the default timeout used by all provider HTTP clients.
const DefaultHTTPTimeout = 120 * time.Second

// HTTPClientPool manages a pool of *http.Client instances keyed by provider
// name. It uses singleflight to ensure only one client is created per key
// even under concurrent access.
//
// Each *http.Client returned is safe for concurrent use: Go's http.Client.Do()
// creates a completely independent HTTP transaction per call — there is no
// request/response caching between calls. The underlying Transport reuses TCP
// connections (keep-alive) for performance, but each request gets its own
// HTTP round-trip with its own headers, body, and response.
type HTTPClientPool struct {
	pool *sync.Map
	sf   singleflight.Group
}

// NewHTTPClientPool returns a ready-to-use pool.
func NewHTTPClientPool() *HTTPClientPool {
	return &HTTPClientPool{
		pool: &sync.Map{},
	}
}

// Get returns (or lazily creates) an *http.Client for the given key with the
// specified timeout. Typical keys are provider names ("openai", "anthropic",
// etc.) so each provider gets its own client and transport instance.
func (p *HTTPClientPool) Get(key string, timeout time.Duration) *http.Client {
	if v, ok := p.pool.Load(key); ok {
		if cl, ok := v.(*http.Client); ok {
			return cl
		}
	}
	v, err, _ := p.sf.Do(key, func() (any, error) {
		if v2, ok := p.pool.Load(key); ok {
			return v2, nil
		}
		cl := &http.Client{
			Timeout:   timeout,
			Transport: newTransport(),
		}
		p.pool.Store(key, cl)
		return cl, nil
	})
	if err != nil {
		return &http.Client{Timeout: timeout, Transport: newTransport()}
	}
	if cl, ok := v.(*http.Client); ok {
		return cl
	}
	return &http.Client{Timeout: timeout, Transport: newTransport()}
}

// DrainBody reads and discards up to 64 KB of remaining data from r, then
// closes it. This ensures the underlying TCP connection is returned cleanly
// to the transport's pool and is never reused with stale data.
// Callers should use this in error paths where the body was only partially
// read (e.g. after io.CopyN for an error preview).
func DrainBody(r io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, 64*1024))
	_ = r.Close()
}

// newTransport returns an *http.Transport with explicit settings tuned for
// high-concurrency provider calls. Each provider key gets its own Transport
// so connection pools are isolated between providers.
func newTransport() *http.Transport {
	return &http.Transport{
		// Connection establishment timeout.
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// TLS handshake timeout.
		TLSHandshakeTimeout: 10 * time.Second,

		// Limit idle connections to prevent unbounded memory growth.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,

		// Drop idle connections after 60s so stale TCP connections from
		// previous requests are never reused after a provider hiccup.
		IdleConnTimeout: 60 * time.Second,

		// If the server doesn't send response headers within 30s after
		// the request is sent, fail fast rather than hanging.
		ResponseHeaderTimeout: 30 * time.Second,

		// Expect-Continue timeout: how long to wait for a 100-continue
		// before sending the body. Keeps large POST bodies from blocking.
		ExpectContinueTimeout: 1 * time.Second,

		// Force HTTP/2 where available for multiplexed requests.
		ForceAttemptHTTP2: true,

		// Disable compression so we get raw JSON (easier to debug and
		// avoids double-decompression issues with streaming).
		DisableCompression: true,
	}
}
