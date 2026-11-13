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

package hashicorp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const secretValue = "sk-live-do-not-leak"

type fakeVault struct {
	mu        sync.Mutex
	logins    int
	renewals  int
	lastLogin map[string]string
	token     string
	lease     int
	renewable bool
	denied    map[string]bool
	versions  map[string]map[string]any
	requests  []string
	namespace string
	failLogin int
	loginDown bool
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		lease:     60,
		renewable: true,
		denied:    map[string]bool{},
		versions:  map[string]map[string]any{"ai-gateway/openai": {"api_key": secretValue, "n": 3}},
	}
}

func (v *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.requests = append(v.requests, r.Method+" "+r.URL.RequestURI())
	v.namespace = r.Header.Get("X-Vault-Namespace")
	write := func(status int, body any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/login"):
		if v.loginDown {
			write(http.StatusServiceUnavailable, nil)
			return
		}
		if v.failLogin > 0 {
			v.failLogin--
			write(http.StatusBadRequest, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		v.lastLogin = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&v.lastLogin)
		v.lastLogin["path"] = r.URL.Path
		v.logins++
		v.token = fmt.Sprintf("hvs.token-%d", v.logins)
		write(http.StatusOK, map[string]any{"auth": map[string]any{"client_token": v.token, "lease_duration": v.lease, "renewable": v.renewable}})
	case r.URL.Path == "/v1/auth/token/renew-self":
		if r.Header.Get("X-Vault-Token") != v.token {
			write(http.StatusForbidden, nil)
			return
		}
		v.renewals++
		write(http.StatusOK, map[string]any{"auth": map[string]any{"client_token": v.token, "lease_duration": v.lease, "renewable": true}})
	case r.URL.Path == "/v1/auth/token/lookup-self":
		if r.Header.Get("X-Vault-Token") != v.token {
			write(http.StatusForbidden, nil)
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{}})
	default:
		if r.Header.Get("X-Vault-Token") != v.token {
			write(http.StatusForbidden, nil)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/kv/data/")
		kv1 := !strings.HasPrefix(r.URL.Path, "/v1/kv/data/")
		if kv1 {
			path = strings.TrimPrefix(r.URL.Path, "/v1/kv1/")
		}
		if v.denied[path] {
			write(http.StatusForbidden, nil)
			return
		}
		data, ok := v.versions[path]
		if !ok {
			write(http.StatusNotFound, map[string]any{"errors": []string{}})
			return
		}
		if kv1 {
			write(http.StatusOK, map[string]any{"data": data})
			return
		}
		write(http.StatusOK, map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 7}}})
	}
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newBackend(t *testing.T, v *fakeVault, cfg secretstore.HashiCorpVaultConfig) (*Backend, *clock) {
	t.Helper()
	srv := httptest.NewServer(v)
	t.Cleanup(srv.Close)
	cfg.Address = srv.URL
	if cfg.Mount == "" {
		cfg.Mount = "kv"
	}
	b, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)}
	b.now = c.Now
	b.readFile = func(path string) ([]byte, error) {
		switch path {
		case DefaultSATokenForTest, "/var/run/jwt":
			return []byte("eyJ.sa.token\n"), nil
		case "/etc/secret_id":
			return []byte("secret-id-1"), nil
		case "/etc/token":
			return []byte(v.currentToken()), nil
		}
		return nil, errors.New("no such file")
	}
	return b, c
}

const DefaultSATokenForTest = secretstore.DefaultServiceAccountTokenFile

func (v *fakeVault) currentToken() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token == "" {
		v.token = "hvs.static"
	}
	return v.token
}

func (v *fakeVault) snapshot() (logins, renewals int, last map[string]string, ns string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.logins, v.renewals, v.lastLogin, v.namespace
}

func k8sAuth() secretstore.VaultAuth {
	return secretstore.VaultAuth{Method: secretstore.VaultAuthKubernetes, Role: "trustgate"}
}

func TestKubernetesLoginAndKV2Read(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Namespace: "admin/ai", Auth: k8sAuth()})
	s, err := b.Fetch(context.Background(), "ai-gateway/openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Select("api_key"); got != secretValue || s.Version() != "7" {
		t.Fatalf("value %q version %q", got, s.Version())
	}
	if _, err := s.Select("n"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("non-string value: %v", err)
	}
	logins, _, last, ns := v.snapshot()
	if logins != 1 || last["path"] != "/v1/auth/kubernetes/login" || last["role"] != "trustgate" || last["jwt"] != "eyJ.sa.token" {
		t.Fatalf("login = %d %v", logins, last)
	}
	if ns != "admin/ai" {
		t.Fatalf("namespace header = %q", ns)
	}
}

func TestLoginMethods(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		auth secretstore.VaultAuth
		path string
		key  string
		want string
	}{
		"jwt":     {secretstore.VaultAuth{Method: secretstore.VaultAuthJWT, Role: "r", JWTFile: "/var/run/jwt", Mount: "oidc/k8s"}, "/v1/auth/oidc/k8s/login", "jwt", "eyJ.sa.token"},
		"approle": {secretstore.VaultAuth{Method: secretstore.VaultAuthAppRole, RoleID: "role-1", SecretIDFile: "/etc/secret_id"}, "/v1/auth/approle/login", "secret_id", "secret-id-1"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := newFakeVault()
			b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: tt.auth})
			if _, err := b.Fetch(context.Background(), "ai-gateway/openai", ""); err != nil {
				t.Fatal(err)
			}
			_, _, last, _ := v.snapshot()
			if last["path"] != tt.path || last[tt.key] != tt.want {
				t.Fatalf("login = %v", last)
			}
		})
	}
	t.Run("token", func(t *testing.T) {
		t.Parallel()
		v := newFakeVault()
		b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthToken, TokenFile: "/etc/token"}})
		if _, err := b.Fetch(context.Background(), "ai-gateway/openai", ""); err != nil {
			t.Fatal(err)
		}
		if logins, _, _, _ := v.snapshot(); logins != 0 {
			t.Fatalf("token auth must not log in, got %d logins", logins)
		}
	})
}

func TestRenewalAndRelogin(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, c := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	ctx := context.Background()
	if _, err := b.Fetch(ctx, "ai-gateway/openai", ""); err != nil {
		t.Fatal(err)
	}
	c.Advance(30 * time.Second)
	if _, err := b.Fetch(ctx, "ai-gateway/openai", ""); err != nil {
		t.Fatal(err)
	}
	if logins, renewals, _, _ := v.snapshot(); logins != 1 || renewals != 0 {
		t.Fatalf("before 2/3 of the lease: logins %d renewals %d", logins, renewals)
	}
	c.Advance(15 * time.Second)
	if _, err := b.Fetch(ctx, "ai-gateway/openai", ""); err != nil {
		t.Fatal(err)
	}
	if logins, renewals, _, _ := v.snapshot(); logins != 1 || renewals != 1 {
		t.Fatalf("after 2/3 of the lease: logins %d renewals %d", logins, renewals)
	}
	c.Advance(61 * time.Second)
	if _, err := b.Fetch(ctx, "ai-gateway/openai", ""); err != nil {
		t.Fatal(err)
	}
	if logins, _, _, _ := v.snapshot(); logins != 2 {
		t.Fatalf("an expired token must log in again, logins %d", logins)
	}

	v.mu.Lock()
	v.token = "revoked-elsewhere"
	v.mu.Unlock()
	c.Advance(reloginGap)
	if _, err := b.Fetch(ctx, "ai-gateway/openai", ""); err != nil {
		t.Fatalf("a 403 on a revoked token must log in again and retry: %v", err)
	}
	if logins, _, _, _ := v.snapshot(); logins != 3 {
		t.Fatalf("logins %d, want 3", logins)
	}
}

func TestFailedReloginIsNotRevocation(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, c := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	if _, err := b.Fetch(context.Background(), "ai-gateway/openai", ""); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	v.token = "revoked-elsewhere"
	v.loginDown = true
	v.mu.Unlock()
	c.Advance(reloginGap)
	_, err := b.Fetch(context.Background(), "ai-gateway/openai", "")
	if !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("a denied read whose re-login hits a 503 = %v, want unavailable so the last value keeps serving", err)
	}
}

func TestDeniedPathIsAccessDeniedWithoutLoginStorm(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	v.denied["ai-gateway/other"] = true
	v.versions["ai-gateway/other"] = map[string]any{"k": "v"}
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	for range 5 {
		if _, err := b.Fetch(context.Background(), "ai-gateway/other", ""); !errors.Is(err, secretstore.ErrAccessDenied) {
			t.Fatalf("denied path: %v", err)
		}
	}
	if logins, _, _, _ := v.snapshot(); logins != 1 {
		t.Fatalf("logins = %d: denied reads must not trigger a login each", logins)
	}
}

func TestReadErrors(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	ctx := context.Background()
	if _, err := b.Fetch(ctx, "ai-gateway/missing", ""); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, version := range []string{"latest", "0", "-1", "1&x=y"} {
		if _, err := b.Fetch(ctx, "ai-gateway/openai", version); !errors.Is(err, secretstore.ErrInvalidPayload) {
			t.Errorf("version %q: %v", version, err)
		}
	}

	failing := newFakeVault()
	failing.failLogin = 1
	fb, _ := newBackend(t, failing, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	if _, err := fb.Fetch(ctx, "ai-gateway/openai", ""); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("failed login: %v", err)
	}
	noFile, _ := newBackend(t, newFakeVault(), secretstore.HashiCorpVaultConfig{Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthAppRole, RoleID: "r", SecretIDFile: "/missing"}})
	if _, err := noFile.Fetch(ctx, "ai-gateway/openai", ""); !errors.Is(err, secretstore.ErrAuthFailed) {
		t.Fatalf("missing credential file: %v", err)
	}

	down, err := New(&secretstore.HashiCorpVaultConfig{Address: "http://127.0.0.1:1", Auth: k8sAuth()})
	if err != nil {
		t.Fatal(err)
	}
	down.readFile = b.readFile
	if _, err := down.Fetch(ctx, "ai-gateway/openai", ""); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("unreachable vault: %v", err)
	}
}

func TestPathsAreEscaped(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	v.versions["ai-gateway/a?b#c"] = map[string]any{"k": "v"}
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	if _, err := b.Fetch(context.Background(), "ai-gateway/a?b#c", "3"); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	last := v.requests[len(v.requests)-1]
	v.mu.Unlock()
	if last != "GET /v1/kv/data/ai-gateway/a%3Fb%23c?version=3" {
		t.Fatalf("request = %q", last)
	}
}

func TestKV1(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Mount: "kv1", KVVersion: 1, Auth: k8sAuth()})
	s, err := b.Fetch(context.Background(), "ai-gateway/openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Select("api_key"); got != secretValue {
		t.Fatalf("value %q", got)
	}
	if _, err := b.Fetch(context.Background(), "ai-gateway/openai", "1"); !errors.Is(err, secretstore.ErrInvalidPayload) {
		t.Fatalf("KV v1 version: %v", err)
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	if err := b.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	for k := range v.versions {
		delete(v.versions, k)
	}
	v.mu.Unlock()
	if err := b.Probe(context.Background()); err != nil {
		t.Fatalf("the probe must not read secrets: %v", err)
	}
}

func TestErrorsNeverCarrySecretsOrTokens(t *testing.T) {
	t.Parallel()
	v := newFakeVault()
	v.denied["ai-gateway/openai"] = true
	b, _ := newBackend(t, v, secretstore.HashiCorpVaultConfig{Auth: k8sAuth()})
	_, err := b.Fetch(context.Background(), "ai-gateway/openai", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, leak := range []string{secretValue, "hvs.", "eyJ.sa.token", "secret-id-1"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error %q leaks %q", err, leak)
		}
	}
}

func TestWaitingForALoginHonoursTheContext(t *testing.T) {
	t.Parallel()
	b, _ := newBackend(t, newFakeVault(), secretstore.HashiCorpVaultConfig{Auth: secretstore.VaultAuth{Method: secretstore.VaultAuthToken, TokenFile: "/etc/token"}})
	b.login <- struct{}{}
	defer func() { <-b.login }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := b.Fetch(ctx, "ai/openai", "")
	if !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("err = %v, want unavailable while another login holds the slot", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("waited %v; the caller must give up when its context ends", waited)
	}
}
