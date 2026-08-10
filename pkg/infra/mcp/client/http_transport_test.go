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

package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCanonicalOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "HTTPS default port", rawURL: "HTTPS://MCP.EXAMPLE.COM/path?x=1", want: "https://mcp.example.com:443"},
		{name: "HTTP default port", rawURL: "http://MCP.EXAMPLE.COM/path", want: "http://mcp.example.com:80"},
		{name: "explicit port", rawURL: "https://MCP.EXAMPLE.COM:8443/path", want: "https://mcp.example.com:8443"},
		{name: "normalized explicit port", rawURL: "https://mcp.example.com:00443/path", want: "https://mcp.example.com:443"},
		{name: "IPv6 default port", rawURL: "https://[2001:DB8::1]/mcp", want: "https://[2001:db8::1]:443"},
		{name: "IPv6 explicit port", rawURL: "http://[2001:db8::1]:8080/mcp", want: "http://[2001:db8::1]:8080"},
		{name: "userinfo", rawURL: "https://user:pass@example.com/mcp", wantErr: true},
		{name: "fragment", rawURL: "https://example.com/mcp#secret", wantErr: true},
		{name: "empty fragment", rawURL: "https://example.com/mcp#", wantErr: true},
		{name: "relative", rawURL: "/mcp", wantErr: true},
		{name: "unsupported scheme", rawURL: "ftp://example.com/mcp", wantErr: true},
		{name: "missing host", rawURL: "https:///mcp", wantErr: true},
		{name: "empty explicit port", rawURL: "https://example.com:/mcp", wantErr: true},
		{name: "invalid port", rawURL: "https://example.com:not-a-port/mcp", wantErr: true},
		{name: "out of range port", rawURL: "https://example.com:65536/mcp", wantErr: true},
		{name: "unbracketed IPv6", rawURL: "https://2001:db8::1/mcp", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := canonicalOrigin(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("canonicalOrigin(%q) = %q, want error", tt.rawURL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalOrigin(%q): %v", tt.rawURL, err)
			}
			if got != tt.want {
				t.Fatalf("canonicalOrigin(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestCanonicalOriginSanitizesParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rawURL   string
		sentinel string
	}{
		{
			name:     "parse failure with query",
			rawURL:   "https://example.com:not-a-port/mcp?token=query-secret-sentinel",
			sentinel: "query-secret-sentinel",
		},
		{
			name:     "invalid userinfo escape",
			rawURL:   "https://userinfo-secret-sentinel%zz@example.com/mcp",
			sentinel: "userinfo-secret-sentinel",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := canonicalOrigin(tt.rawURL)
			if err == nil {
				t.Fatal("expected invalid URL error")
			}
			if strings.Contains(err.Error(), tt.sentinel) {
				t.Fatalf("error exposed raw URL data: %v", err)
			}
		})
	}
}

func TestTargetHTTPClientRejectsReservedHeaders(t *testing.T) {
	t.Parallel()

	headers := []string{
		"Host",
		"Connection",
		"Content-Length",
		"Transfer-Encoding",
		"Trailer",
		"Content-Type",
		"Accept",
		"User-Agent",
		"Mcp-Protocol-Version",
		"Mcp-Session-Id",
		"Last-Event-ID",
		"Mcp-Method",
		"Mcp-Name",
		"Mcp-Param-Tool",
		"mCP-pArAm-tenant",
	}

	for _, header := range headers {
		t.Run(header, func(t *testing.T) {
			t.Parallel()
			if _, err := newTargetHTTPClient(map[string]string{header: "override"}); err == nil {
				t.Fatalf("newTargetHTTPClient accepted reserved header %q", header)
			}
		})
	}

	if _, err := newTargetHTTPClient(map[string]string{
		"Authorization": "Bearer token",
		"X-Tenant-ID":   "tenant",
	}); err != nil {
		t.Fatalf("newTargetHTTPClient rejected allowed headers: %v", err)
	}
}

func TestTargetHTTPClientRejectsDuplicateHeaderCasingBeforeIO(t *testing.T) {
	t.Parallel()

	transport := &recordingRoundTripper{}
	for range 20 {
		_, err := newTargetHTTPClientWithTransport(map[string]string{
			"Authorization": "Bearer first",
			"authorization": "Bearer second",
		}, transport)
		if err == nil || err.Error() != `duplicate upstream header "authorization"` {
			t.Fatalf("error = %v, want deterministic duplicate header error", err)
		}
	}
	if got := len(transport.snapshot()); got != 0 {
		t.Fatalf("transport requests = %d, want 0", got)
	}
}

type recordingRoundTripper struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req.Clone(context.Background()))
	r.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Request:    req,
	}, nil
}

func (r *recordingRoundTripper) snapshot() []*http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*http.Request(nil), r.requests...)
}

func TestTargetHTTPClientClonesRequestsAndIsolatesHeaders(t *testing.T) {
	t.Parallel()

	shared := &recordingRoundTripper{}
	firstHeaders := map[string]string{"Authorization": "Bearer first", "X-Tenant-ID": "one"}
	first, err := newTargetHTTPClientWithTransport(firstHeaders, shared)
	if err != nil {
		t.Fatalf("first client: %v", err)
	}
	second, err := newTargetHTTPClientWithTransport(
		map[string]string{"Authorization": "Bearer second", "X-Tenant-ID": "two"},
		shared,
	)
	if err != nil {
		t.Fatalf("second client: %v", err)
	}
	firstHeaders["Authorization"] = "Bearer mutated"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://example.com/mcp", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Caller", "preserved")
	if _, err := first.Do(req); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := second.Do(req); err != nil {
		t.Fatalf("second request: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("original request authorization = %q, want empty", got)
	}
	recorded := shared.snapshot()
	if len(recorded) != 2 {
		t.Fatalf("recorded requests = %d, want 2", len(recorded))
	}
	if got := recorded[0].Header.Get("Authorization"); got != "Bearer first" {
		t.Fatalf("first authorization = %q", got)
	}
	if got := recorded[1].Header.Get("Authorization"); got != "Bearer second" {
		t.Fatalf("second authorization = %q", got)
	}
	if recorded[0].Header.Get("X-Tenant-ID") == recorded[1].Header.Get("X-Tenant-ID") {
		t.Fatal("target-scoped tenant headers leaked across clients")
	}
	if recorded[0].Header.Get("X-Caller") != "preserved" || recorded[1].Header.Get("X-Caller") != "preserved" {
		t.Fatal("base request headers were not preserved")
	}
}

func TestTargetHTTPClientRejectsRedirects(t *testing.T) {
	t.Parallel()

	var redirected atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	t.Cleanup(destination.Close)

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	client, err := newTargetHTTPClient(nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, source.URL, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	_, err = client.Do(req)
	if !errors.Is(err, errRedirectRejected) {
		t.Fatalf("redirect error = %v, want errRedirectRejected", err)
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect destination contacted %d times", redirected.Load())
	}
}
