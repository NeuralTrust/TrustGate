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
	"context"
	"net/http"
)

type forwardedHeadersKey struct{}

// WithForwardedHeaders carries client request headers a registry chose to
// forward (registry.ForwardClientHeaders) to every provider request made with
// ctx through an HTTPClientPool client. An empty header leaves ctx as is.
func WithForwardedHeaders(ctx context.Context, h http.Header) context.Context {
	if len(h) == 0 {
		return ctx
	}
	return context.WithValue(ctx, forwardedHeadersKey{}, h)
}

func forwardedHeaders(ctx context.Context) http.Header {
	h, _ := ctx.Value(forwardedHeadersKey{}).(http.Header)
	return h
}

// forwardingTransport adds the forwarded client headers to an outbound
// provider request. A header the provider client already set (its
// credentials, anthropic-version, an operator's static header) is never
// replaced: what the gateway decided about the provider request wins over
// what the caller sent.
type forwardingTransport struct {
	base *http.Transport
}

func (t *forwardingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := forwardedHeaders(req.Context())
	if len(h) == 0 {
		return t.base.RoundTrip(req)
	}
	// A RoundTripper must not modify the request it was given.
	var out *http.Request
	for name, values := range h {
		if len(values) == 0 || len(req.Header.Values(name)) > 0 {
			continue
		}
		if out == nil {
			out = req.Clone(req.Context())
		}
		out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	if out == nil {
		return t.base.RoundTrip(req)
	}
	return t.base.RoundTrip(out)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the pool.
func (t *forwardingTransport) CloseIdleConnections() {
	t.base.CloseIdleConnections()
}
