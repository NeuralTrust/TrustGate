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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewHTTPClientRefusesLoopbackUnlessAllowed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()

	SetAllowPrivate(false)
	t.Cleanup(func() { SetAllowPrivate(false) })

	_, err := NewHTTPClient(time.Second).Get(srv.URL)
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("err = %v, want ErrBlockedDestination", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hit %d times, want 0", hits.Load())
	}

	SetAllowPrivate(true)
	resp, err := NewHTTPClient(time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
}

func TestCheckRedirect(t *testing.T) {
	mk := func(method, url string, hdr map[string]string) *http.Request {
		r, _ := http.NewRequest(method, url, strings.NewReader("client_secret=x"))
		if method == http.MethodGet {
			r, _ = http.NewRequest(method, url, nil)
		}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	tests := []struct {
		name    string
		first   *http.Request
		next    *http.Request
		hops    int
		blocked bool
	}{
		{"same host POST follows", mk("POST", "https://idp.example/token", nil), mk("POST", "https://idp.example/v2/token", nil), 1, false},
		{"cross host POST refused", mk("POST", "https://idp.example/token", nil), mk("POST", "https://other.example/token", nil), 1, true},
		{"cross host GET allowed", mk("GET", "https://idp.example/.well-known", nil), mk("GET", "https://cdn.example/doc", nil), 1, false},
		{"cross host GET with Authorization refused", mk("GET", "https://idp.example/u", map[string]string{"Authorization": "Bearer t"}), mk("GET", "https://cdn.example/u", nil), 1, true},
		{"https to http downgrade refused", mk("GET", "https://idp.example/a", nil), mk("GET", "http://idp.example/a", nil), 1, true},
		{"chain cap", mk("GET", "https://idp.example/a", nil), mk("GET", "https://idp.example/b", nil), maxRedirects, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			via := make([]*http.Request, tt.hops)
			for i := range via {
				via[i] = tt.first
			}
			err := CheckRedirect(tt.next, via)
			if (err != nil) != tt.blocked {
				t.Fatalf("CheckRedirect err = %v, blocked want %v", err, tt.blocked)
			}
		})
	}
}

func TestNewHTTPClientTrustedContextSkipsTheGuardOnlyWhenMarked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	prev := AllowPrivate()
	t.Cleanup(func() { SetAllowPrivate(prev) })
	SetAllowPrivate(false)
	client := NewHTTPClient(time.Second)

	req, _ := http.NewRequestWithContext(TrustedIf(context.Background(), true), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("trusted request: %v", err)
	}
	_ = resp.Body.Close()

	// The same client, same URL, unmarked context: still refused, and the
	// connection opened for the trusted request is not reused for it.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if _, err := client.Do(req); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("untrusted request err = %v, want ErrBlockedDestination", err)
	}
	if IsTrusted(TrustedIf(context.Background(), false)) {
		t.Fatal("TrustedIf(false) must not mark the context")
	}
	if IsTrusted(TrustedIf(TrustedIf(context.Background(), true), false)) {
		t.Fatal("trust must not be sticky: a tenant-scoped call clears an outer operator mark")
	}
}
