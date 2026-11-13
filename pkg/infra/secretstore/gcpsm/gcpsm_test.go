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

package gcpsm_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/gcpsm"
)

type tokens struct{ err error }

func (t tokens) Token(context.Context, string) (string, error) { return "ya29.token", t.err }

type fakeSM struct {
	mu       sync.Mutex
	requests []string
	auth     string
	status   int
	crc      string
}

func (f *fakeSM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.EscapedPath())
	f.auth = r.Header.Get("Authorization")
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"error":{"message":"secret sk-live"}}`))
		return
	}
	data := []byte(`{"key":"sk-live"}`)
	crc := strconv.FormatUint(uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))), 10)
	if f.crc != "" {
		crc = f.crc
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":    "projects/123/secrets/llm-openai/versions/4",
		"payload": map[string]any{"data": base64.StdEncoding.EncodeToString(data), "dataCrc32c": crc},
	})
}

func newBackend(t *testing.T, f *fakeSM, tok gcpsm.TokenSource) *gcpsm.Backend {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	b, err := gcpsm.NewWithTokenSource(&secretstore.GCPSecretManagerConfig{ProjectID: "acme-ai"}, tok, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFetch(t *testing.T) {
	t.Parallel()
	f := &fakeSM{}
	b := newBackend(t, f, tokens{})
	ctx := context.Background()

	s, err := b.Fetch(ctx, "llm-openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Select("key"); v != "sk-live" || s.Version() != "4" {
		t.Fatalf("value %q version %q", v, s.Version())
	}
	if _, err := b.Fetch(ctx, "projects/other-proj/secrets/llm-x", "3"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	reqs, auth := f.requests, f.auth
	f.mu.Unlock()
	if reqs[0] != "/v1/projects/acme-ai/secrets/llm-openai/versions/latest:access" ||
		reqs[1] != "/v1/projects/other-proj/secrets/llm-x/versions/3:access" || auth != "Bearer ya29.token" {
		t.Fatalf("requests %v auth %q", reqs, auth)
	}
	for _, path := range []string{"a/b", "projects/p/secrets", "projects/p/secrets/s/versions/1", "../x"} {
		if _, err := b.Fetch(ctx, path, ""); !errors.Is(err, secretstore.ErrNotFound) {
			t.Errorf("path %q: %v", path, err)
		}
	}
}

func TestVersionIsEscaped(t *testing.T) {
	t.Parallel()
	f := &fakeSM{}
	b := newBackend(t, f, tokens{})
	_, _ = b.Fetch(context.Background(), "llm-openai", "1/../../x")
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.requests[0]; got != "/v1/projects/acme-ai/secrets/llm-openai/versions/1%2F..%2F..%2Fx:access" {
		t.Fatalf("request = %q", got)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]error{
		http.StatusNotFound:            secretstore.ErrNotFound,
		http.StatusForbidden:           secretstore.ErrAccessDenied,
		http.StatusUnauthorized:        secretstore.ErrAuthFailed,
		http.StatusTooManyRequests:     secretstore.ErrUnavailable,
		http.StatusServiceUnavailable:  secretstore.ErrUnavailable,
		http.StatusBadRequest:          secretstore.ErrNotFound,
		http.StatusInternalServerError: secretstore.ErrUnavailable,
	} {
		b := newBackend(t, &fakeSM{status: status}, tokens{})
		_, err := b.Fetch(context.Background(), "llm-openai", "")
		if !errors.Is(err, want) {
			t.Errorf("status %d -> %v, want %v", status, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "sk-live") {
			t.Errorf("error %q carries the response body", err)
		}
	}
	if _, err := newBackend(t, &fakeSM{crc: "1"}, tokens{}).Fetch(context.Background(), "llm-openai", ""); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Errorf("bad checksum: %v", err)
	}
	if _, err := newBackend(t, &fakeSM{}, tokens{err: errors.New("no ADC")}).Fetch(context.Background(), "llm-openai", ""); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Errorf("token failure: %v", err)
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()
	if err := newBackend(t, &fakeSM{}, tokens{}).Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := newBackend(t, &fakeSM{}, tokens{err: errors.New("x")}).Probe(context.Background()); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("probe: %v", err)
	}
}
