// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netguard

import (
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// allowPrivate is the operator escape hatch (OUTBOUND_ALLOW_PRIVATE_NETWORKS)
// shared by every outbound client a tenant can steer: provider base_url, OAuth
// and OIDC endpoints, telemetry exporters. It is read on every dial, so a change
// applies to pooled connections too.
var allowPrivate atomic.Bool

// SetAllowPrivate lets the shared guard reach private, loopback and link-local
// addresses. Leave it off on multi-tenant gateways; enable it for a
// single-tenant or self-hosted deployment whose upstreams live on a private
// network. Call it during initialization.
func SetAllowPrivate(allow bool) { allowPrivate.Store(allow) }

// AllowPrivate reports the current state of the operator escape hatch.
func AllowPrivate() bool { return allowPrivate.Load() }

// shared dials every connection of the clients built by this package.
var shared = New(
	&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	allowPrivate.Load,
)

// Shared returns the process-wide guard bound to the operator escape hatch.
func Shared() *Guard { return shared }

// NewTransport returns an http.Transport whose dials go through the shared
// guard.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialContext:           shared.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          20,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// maxRedirects bounds a redirect chain followed by a guarded client.
const maxRedirects = 5

// NewHTTPClient returns an http.Client for a URL a tenant can influence. Every
// dial, redirects included, is checked against the shared guard.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     NewTransport(),
		CheckRedirect: CheckRedirect,
	}
}

// CheckRedirect caps the chain and refuses hops that would leak credentials: a
// scheme downgrade, or any cross-host hop of a request that carries a body or
// an Authorization header (307/308 would otherwise replay client_secret or
// subject_token to the new host). Redirects of body-less GETs stay allowed
// because identity providers legitimately redirect discovery documents.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	first := via[0]
	if first.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return http.ErrUseLastResponse
	}
	if req.URL.Host != first.URL.Host && (carriesCredentials(first)) {
		return http.ErrUseLastResponse
	}
	return nil
}

func carriesCredentials(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return true
	}
	return req.Header.Get("Authorization") != ""
}
