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

package httpclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

func TestStatusError(t *testing.T) {
	t.Parallel()
	tests := map[int]error{
		http.StatusNotFound:            secretstore.ErrNotFound,
		http.StatusBadRequest:          secretstore.ErrNotFound,
		http.StatusUnauthorized:        secretstore.ErrAuthFailed,
		http.StatusForbidden:           secretstore.ErrAccessDenied,
		http.StatusTemporaryRedirect:   secretstore.ErrUnavailable,
		http.StatusMovedPermanently:    secretstore.ErrUnavailable,
		http.StatusMethodNotAllowed:    secretstore.ErrUnavailable,
		http.StatusConflict:            secretstore.ErrUnavailable,
		http.StatusPreconditionFailed:  secretstore.ErrUnavailable,
		http.StatusTooManyRequests:     secretstore.ErrUnavailable,
		http.StatusInternalServerError: secretstore.ErrUnavailable,
		http.StatusServiceUnavailable:  secretstore.ErrUnavailable,
	}
	for status, want := range tests {
		if err := httpclient.StatusError(status); !errors.Is(err, want) {
			t.Errorf("StatusError(%d) = %v, want %v", status, err, want)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed with token %q", r.Header.Get("X-Vault-Token"))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()
	client, err := httpclient.New("")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, redirect.URL, nil)
	req.Header.Set("X-Vault-Token", "hvs.secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	httpclient.Discard(resp)
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestCAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := httpclient.New(filepath.Join(dir, "missing.crt")); !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("missing CA: %v", err)
	}
	bad := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := httpclient.New(bad); !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("bad CA: %v", err)
	}
}

func TestNewLeavesTheResponseDeadlineToTheContext(t *testing.T) {
	c, err := httpclient.New("")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Transport.(*http.Transport).ResponseHeaderTimeout; got != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v; a fixed deadline would cap SECRET_STORES_FETCH_TIMEOUT", got)
	}
}
