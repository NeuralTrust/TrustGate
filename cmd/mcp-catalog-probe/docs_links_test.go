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

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func docsCheckClient() *http.Client {
	return &http.Client{
		Timeout: time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestCheckDocsLink(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/gone", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/bot", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := docsCheckClient()

	if got := checkDocsLink(client, time.Second, srv.URL+"/ok"); got != "" {
		t.Fatalf("resolving link reported %q", got)
	}
	if got := checkDocsLink(client, time.Second, srv.URL+"/moved"); !strings.Contains(got, "redirects to /docs/") {
		t.Fatalf("redirected link = %q, want the redirect target", got)
	}
	if got := checkDocsLink(client, time.Second, srv.URL+"/gone"); got != "HTTP 404" {
		t.Fatalf("missing page = %q, want HTTP 404", got)
	}
	if got := checkDocsLink(client, time.Second, srv.URL+"/bot"); got != "" {
		t.Fatalf("bot protection must not be reported as broken, got %q", got)
	}
}
