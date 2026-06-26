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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tokenServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tokenPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTokenManagerConfigured(t *testing.T) {
	t.Parallel()
	if newTokenManager(http.DefaultClient, "", "").configured() {
		t.Fatal("empty credentials must report not configured")
	}
	if newTokenManager(http.DefaultClient, "id", "  ").configured() {
		t.Fatal("blank secret must report not configured")
	}
	if !newTokenManager(http.DefaultClient, "id", "secret").configured() {
		t.Fatal("set credentials must report configured")
	}
}

func TestTokenManagerCachesToken(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := tokenServer(t, &hits)
	m := newTokenManager(srv.Client(), "id", "secret")

	for i := 0; i < 3; i++ {
		tok, err := m.token(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if tok != "tok" {
			t.Fatalf("token = %q, want tok", tok)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1 (cached)", got)
	}
}

func TestTokenManagerInvalidateForcesRefetch(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := tokenServer(t, &hits)
	m := newTokenManager(srv.Client(), "id", "secret")

	if _, err := m.token(context.Background(), srv.URL); err != nil {
		t.Fatalf("token: %v", err)
	}
	m.invalidate(srv.URL)
	if _, err := m.token(context.Background(), srv.URL); err != nil {
		t.Fatalf("token after invalidate: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("token endpoint hits = %d, want 2 (refetch after invalidate)", got)
	}
}

func TestTokenManagerSingleFlight(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	t.Cleanup(srv.Close)
	m := newTokenManager(srv.Client(), "id", "secret")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.token(context.Background(), srv.URL); err != nil {
				t.Errorf("token: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("concurrent refresh hits = %d, want 1 (single-flight)", got)
	}
}
