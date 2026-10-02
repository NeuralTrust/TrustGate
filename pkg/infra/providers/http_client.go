// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package providers

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

// DefaultHTTPTimeout is the timeout used by all provider HTTP clients.
// Override with SetDefaultHTTPTimeout during initialization.
var DefaultHTTPTimeout = 120 * time.Second

// DefaultResponseHeaderTimeout bounds the wait for an upstream provider's
// response headers. Override with SetDefaultResponseHeaderTimeout during
// initialization.
//
// Non-streaming providers withhold response headers until the whole completion
// has been generated, so this value caps total generation time for
// non-streaming requests. Keeping it below DefaultHTTPTimeout silently
// truncates long completions regardless of the configured request timeout.
var DefaultResponseHeaderTimeout = 120 * time.Second

func SetDefaultHTTPTimeout(d time.Duration) {
	if d > 0 {
		DefaultHTTPTimeout = d
	}
}

// SetAllowPrivateNetworks lets provider clients reach private, loopback and
// link-local addresses. It drives the shared netguard escape hatch
// (OUTBOUND_ALLOW_PRIVATE_NETWORKS), which every tenant-steerable outbound
// client reads. Call it during initialization.
func SetAllowPrivateNetworks(allow bool) {
	netguard.SetAllowPrivate(allow)
}

func SetDefaultResponseHeaderTimeout(d time.Duration) {
	if d > 0 {
		DefaultResponseHeaderTimeout = d
	}
}

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
	// trusted pools dial operator-configured destinations and skip the
	// private-network guard. Never use one for a URL a tenant can set.
	trusted bool
}

// NewHTTPClientPool returns a ready-to-use pool whose connections refuse
// private, loopback and link-local destinations (see SetAllowPrivateNetworks).
// Use it for any URL a tenant can influence, provider base_url included.
func NewHTTPClientPool() *HTTPClientPool {
	return &HTTPClientPool{
		pool: &sync.Map{},
	}
}

// NewTrustedHTTPClientPool returns a pool for destinations the operator fixed
// through gateway configuration (for example OPENAI_MODERATION_BASE_URL), which
// may legitimately be in-cluster. It applies the same transport tuning as
// NewHTTPClientPool without the private-network guard. Never use it for a URL a
// tenant can set.
func NewTrustedHTTPClientPool() *HTTPClientPool {
	return &HTTPClientPool{
		pool:    &sync.Map{},
		trusted: true,
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
			Transport: newTransport(p.trusted),
		}
		p.pool.Store(key, cl)
		return cl, nil
	})
	if err != nil {
		return &http.Client{Timeout: timeout, Transport: newTransport(p.trusted)}
	}
	if cl, ok := v.(*http.Client); ok {
		return cl
	}
	return &http.Client{Timeout: timeout, Transport: newTransport(p.trusted)}
}

// GetStream returns an *http.Client suitable for SSE streaming. Unlike Get, it
// has no overall client timeout (a streamed response can outlive
// DefaultHTTPTimeout); callers bound the stream with a context deadline
// instead. Stream clients are pooled under a distinct key so they never share
// the non-streaming client's timeout.
func (p *HTTPClientPool) GetStream(key string) *http.Client {
	return p.Get(key+"-stream", 0)
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
func newTransport(trusted bool) *http.Transport {
	dial := netguard.Shared().DialContext
	if trusted {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Transport{
		DialContext: dial,

		TLSHandshakeTimeout: 10 * time.Second,

		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,

		IdleConnTimeout: 60 * time.Second,

		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,

		ExpectContinueTimeout: 1 * time.Second,

		ForceAttemptHTTP2: true,

		DisableCompression: true,
	}
}
