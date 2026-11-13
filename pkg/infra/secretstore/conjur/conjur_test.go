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

package conjur

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type fakeConjur struct {
	mu       sync.Mutex
	logins   atomic.Int64
	revoked  bool
	lastAuth string
	lastBody string
	reads    []string
	status   int
}

func (f *fakeConjur) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.EscapedPath() {
	case "/authn-jwt/trustgate/acme/authenticate", "/authn/acme/host%2Ftrustgate/authenticate":
		raw, _ := io.ReadAll(r.Body)
		f.lastAuth, f.lastBody = r.URL.EscapedPath(), string(raw)
		if r.Header.Get("Accept-Encoding") != "base64" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := f.logins.Add(1)
		f.revoked = false
		_, _ = w.Write([]byte("dG9rZW4t" + string(rune('0'+n))))
		return
	}
	if r.Header.Get("Authorization") == "" || f.revoked {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.reads = append(f.reads, r.URL.EscapedPath()+"?"+r.URL.RawQuery+" "+r.Header.Get("Authorization"))
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	_, _ = w.Write([]byte(`{"api_key":"sk-conjur"}`))
}

type clock struct{ now time.Time }

func newConjur(t *testing.T, f *fakeConjur, auth secretstore.ConjurAuth) (*Backend, *clock) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	b, err := New(&secretstore.CyberArkConjurConfig{URL: srv.URL, Account: "acme", Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	b.client, b.now = srv.Client(), func() time.Time { return c.now }
	b.readFile = func(path string) ([]byte, error) {
		switch path {
		case secretstore.DefaultServiceAccountTokenFile:
			return []byte("eyJ.sa.token\n"), nil
		case "/etc/conjur/api-key":
			return []byte("host-api-key\n"), nil
		}
		return nil, errors.New("missing")
	}
	return b, c
}

func TestJWTAuthenticationAndRead(t *testing.T) {
	t.Parallel()
	f := &fakeConjur{}
	b, c := newConjur(t, f, secretstore.ConjurAuth{Method: secretstore.ConjurAuthJWT, ServiceID: "trustgate"})

	secret, err := b.Fetch(context.Background(), "ai-gateway/openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := secret.Select("api_key"); err != nil || v != "sk-conjur" {
		t.Fatalf("value %q err %v", v, err)
	}
	if f.lastBody != "jwt=eyJ.sa.token" {
		t.Fatalf("authn-jwt body = %q", f.lastBody)
	}
	if f.reads[0] != `/secrets/acme/variable/ai-gateway%2Fopenai? Token token="dG9rZW4t1"` {
		t.Fatalf("read = %q; the variable id must stay one segment", f.reads[0])
	}

	if _, err := b.Fetch(context.Background(), "ai-gateway/openai", "3"); err != nil || f.logins.Load() != 1 {
		t.Fatalf("a fresh token is reused: logins %d err %v", f.logins.Load(), err)
	}
	if f.reads[1] != `/secrets/acme/variable/ai-gateway%2Fopenai?version=3 Token token="dG9rZW4t1"` {
		t.Fatalf("versioned read = %q", f.reads[1])
	}
	c.now = c.now.Add(tokenRefreshAfter)
	if _, err := b.Fetch(context.Background(), "ai-gateway/openai", ""); err != nil || f.logins.Load() != 2 {
		t.Fatalf("a token past two thirds of its life is renewed: logins %d err %v", f.logins.Load(), err)
	}
}

func TestAPIKeyAuthentication(t *testing.T) {
	t.Parallel()
	f := &fakeConjur{}
	b, _ := newConjur(t, f, secretstore.ConjurAuth{Method: secretstore.ConjurAuthAPIKey, Login: "host/trustgate", APIKeyFile: "/etc/conjur/api-key"})
	if err := b.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.lastAuth != "/authn/acme/host%2Ftrustgate/authenticate" || f.lastBody != "host-api-key" {
		t.Fatalf("authn = %q body %q", f.lastAuth, f.lastBody)
	}
}

func TestRevokedTokenAuthenticatesOnce(t *testing.T) {
	t.Parallel()
	f := &fakeConjur{}
	b, _ := newConjur(t, f, secretstore.ConjurAuth{ServiceID: "trustgate"})
	if _, err := b.Fetch(context.Background(), "x", ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.revoked = true
	f.mu.Unlock()
	if _, err := b.Fetch(context.Background(), "x", ""); err != nil || f.logins.Load() != 2 {
		t.Fatalf("a 401 on a read authenticates again once: logins %d err %v", f.logins.Load(), err)
	}
}

func TestFailuresKeepTheirClass(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]error{
		http.StatusNotFound:           secretstore.ErrNotFound,
		http.StatusForbidden:          secretstore.ErrAccessDenied,
		http.StatusServiceUnavailable: secretstore.ErrUnavailable,
	} {
		f := &fakeConjur{status: status}
		b, _ := newConjur(t, f, secretstore.ConjurAuth{ServiceID: "trustgate"})
		if _, err := b.Fetch(context.Background(), "x", ""); !errors.Is(err, want) {
			t.Errorf("status %d: %v, want %v", status, err, want)
		}
	}
	b, _ := newConjur(t, &fakeConjur{}, secretstore.ConjurAuth{ServiceID: "trustgate", JWTFile: "/nope"})
	if err := b.Probe(context.Background()); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("missing token file: %v", err)
	}
	b, _ = newConjur(t, &fakeConjur{}, secretstore.ConjurAuth{ServiceID: "trustgate"})
	if _, err := b.Fetch(context.Background(), "x", "v2"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("a non-numeric version: %v", err)
	}
}
