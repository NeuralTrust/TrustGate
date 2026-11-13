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

package localfile_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/localfile"
)

const validFile = `version: 1
stores:
  - name: corp-vault
    type: hashicorp_vault
    allowed_paths: ["ai-gateway/"]
    gateways: ["0193f0c2-6c1e-7c3a-9b2f-1d2e3f4a5b6c"]
    cache: { ttl: 10m, max_stale: 1h, negative_ttl: 1m }
    hashicorp_vault:
      address: https://vault.internal:8200
      namespace: admin/ai
      mount: kv
      kv_version: 2
      auth:
        method: approle
        role_id: r
        secret_id_file: /etc/trustgate/secret-stores/corp-vault/secret_id
  - name: aws
    type: aws_secrets_manager
    allowed_paths: ["prod/llm/"]
    aws_secrets_manager: { region: eu-west-1 }
  - name: gcp
    type: gcp_secret_manager
    allowed_paths: ["llm-"]
    gcp_secret_manager: { project_id: acme-ai }
  - name: k8s
    type: file
    allowed_paths: ["*"]
    file: { root: /var/run/trustgate/secrets }
  - name: env
    type: env
    allowed_paths: ["*"]
    env: { prefix: TG_SECRET_ }
`

func TestParseValid(t *testing.T) {
	t.Parallel()
	stores, err := localfile.Parse([]byte(validFile))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(stores) != 5 {
		t.Fatalf("stores = %d, want 5", len(stores))
	}
	vault := stores[0]
	cfg, ok := vault.Config.(*secretstore.HashiCorpVaultConfig)
	if !ok || cfg.Namespace != "admin/ai" || cfg.EffectiveMount() != "kv" || cfg.Auth.SecretIDFile == "" {
		t.Fatalf("vault config = %+v", vault.Config)
	}
	if vault.Cache.TTL != 10*time.Minute || vault.Cache.MaxStale != time.Hour || vault.Cache.NegativeTTL != time.Minute {
		t.Fatalf("cache = %+v", vault.Cache)
	}
	if len(vault.Gateways) != 1 || vault.Gateways[0].String() != "0193f0c2-6c1e-7c3a-9b2f-1d2e3f4a5b6c" {
		t.Fatalf("gateways = %v", vault.Gateways)
	}
}

func TestParseAzureAndConjur(t *testing.T) {
	t.Parallel()
	stores, err := localfile.Parse([]byte(`version: 1
stores:
  - name: azure
    type: azure_key_vault
    allowed_paths: ["llm-"]
    azure_key_vault: { vault_url: "https://acme-ai.vault.azure.net/", client_id: "00000000-0000-0000-0000-000000000001" }
  - name: conjur
    type: cyberark_conjur
    allowed_paths: ["ai-gateway/"]
    cyberark_conjur:
      url: https://conjur.internal
      account: acme
      auth: { method: jwt, service_id: trustgate }
  - name: conjur-key
    type: cyberark_conjur
    allowed_paths: ["*"]
    cyberark_conjur:
      url: https://conjur.internal
      account: acme
      auth: { method: api_key, login: host/trustgate, api_key_file: /etc/conjur/api-key }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	az, ok := stores[0].Config.(*secretstore.AzureKeyVaultConfig)
	if !ok {
		t.Fatalf("azure config = %T", stores[0].Config)
	}
	if aud, err := az.Audience(); err != nil || aud != "https://vault.azure.net/.default" {
		t.Fatalf("audience = %q, %v", aud, err)
	}
	cj, ok := stores[1].Config.(*secretstore.CyberArkConjurConfig)
	if !ok || cj.Auth.EffectiveJWTFile() != secretstore.DefaultServiceAccountTokenFile {
		t.Fatalf("conjur config = %+v", stores[1].Config)
	}
}

func TestParseRefuses(t *testing.T) {
	t.Parallel()
	store := func(body string) string {
		return "version: 1\nstores:\n  - name: s\n    allowed_paths: [\"*\"]\n" + body
	}
	tests := []struct {
		name    string
		raw     string
		mention string
	}{
		{"empty", "", "empty"},
		{"wrong version", "version: 2\nstores: []\n", "version"},
		{"two documents", "version: 1\nstores: []\n---\nversion: 1\n", "single YAML document"},
		{"unknown top-level key", "version: 1\nstorez: []\n", "storez"},
		{"inline vault token", store("    type: hashicorp_vault\n    hashicorp_vault: { address: https://v, auth: { method: token, token: s3cr3t } }\n"), `store "s": hashicorp_vault.auth.token must not be written inline`},
		{"inline secret_id", store("    type: hashicorp_vault\n    hashicorp_vault: { address: https://v, auth: { method: approle, role_id: r, secret_id: s3cr3t } }\n"), "auth.secret_id"},
		{"inline jwt", store("    type: hashicorp_vault\n    hashicorp_vault: { address: https://v, auth: { method: jwt, role: r, jwt: e } }\n"), "auth.jwt"},
		{"unknown store key", store("    type: env\n    env: { prefix: TG_ }\n    ttl: 5m\n"), "ttl"},
		{"unknown config key", store("    type: env\n    env: { prefix: TG_, suffix: X }\n"), "suffix"},
		{"azure host", store("    type: azure_key_vault\n    azure_key_vault: { vault_url: https://a.example.com }\n"), "Key Vault host"},
		{"azure http", store("    type: azure_key_vault\n    azure_key_vault: { vault_url: http://a.vault.azure.net }\n"), "vault_url"},
		{"conjur without service id", store("    type: cyberark_conjur\n    cyberark_conjur: { url: https://c, account: acme }\n"), "service_id"},
		{"conjur api key inline", store("    type: cyberark_conjur\n    cyberark_conjur: { url: https://c, account: acme, auth: { method: api_key, login: host/tg, api_key: k } }\n"), "api_key"},
		{"conjur k8s", store("    type: cyberark_conjur\n    cyberark_conjur: { url: https://c, account: acme, auth: { method: k8s } }\n"), "auth.method"},
		{"conjur second block", store("    type: env\n    env: { prefix: TG_ }\n    cyberark_conjur: { url: https://c }\n"), "exactly one type block"},
		{"missing block", store("    type: env\n"), "env block is missing"},
		{"two blocks", store("    type: env\n    env: { prefix: TG_ }\n    file: { root: /x }\n"), "exactly one type block"},
		{"mismatched block", store("    type: env\n    file: { root: /x }\n"), "does not match"},
		{"bad gateway", store("    type: env\n    env: { prefix: TG_ }\n    gateways: [team-a]\n"), "not a gateway id"},
		{"bad duration", store("    type: env\n    env: { prefix: TG_ }\n    cache: { ttl: forever }\n"), "cache.ttl"},
		{"ttl too short", store("    type: env\n    env: { prefix: TG_ }\n    cache: { ttl: 1s }\n"), "cache.ttl must be at least"},
		{"invalid store", store("    type: env\n    env: { prefix: \"\" }\n"), "env.prefix"},
		{"duplicate", "version: 1\nstores:\n  - { name: s, type: env, allowed_paths: [\"*\"], env: { prefix: A_ } }\n  - { name: s, type: env, allowed_paths: [\"*\"], env: { prefix: B_ } }\n", "declared twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := localfile.Parse([]byte(tt.raw))
			if !errors.Is(err, secretstore.ErrInvalidStore) || !strings.Contains(err.Error(), tt.mention) {
				t.Fatalf("Parse() = %v, want ErrInvalidStore mentioning %q", err, tt.mention)
			}
		})
	}
}

func TestParseErrorsDoNotEchoValues(t *testing.T) {
	t.Parallel()
	raw := "version: 1\nstores:\n  - name: v\n    type: hashicorp_vault\n    allowed_paths: [\"*\"]\n    hashicorp_vault: { address: https://v, kv_version: sk-live-pasted-here, auth: { method: kubernetes, role: r } }\n"
	_, err := localfile.Parse([]byte(raw))
	if err == nil || strings.Contains(err.Error(), "sk-live-pasted-here") {
		t.Fatalf("Parse() = %v, must fail without echoing the value", err)
	}
}

func TestInlineCheckIgnoresFileKeys(t *testing.T) {
	t.Parallel()
	raw := "version: 1\nstores:\n  - name: v\n    type: hashicorp_vault\n    allowed_paths: [\"*\"]\n    hashicorp_vault: { address: https://v, auth: { method: token, token_file: /etc/t } }\n"
	if _, err := localfile.Parse([]byte(raw)); err != nil {
		t.Fatalf("token_file refused: %v", err)
	}
}

type fakeBackend struct{ name string }

func (fakeBackend) Fetch(context.Context, string, string) (secretstore.Secret, error) {
	return secretstore.Secret{}, nil
}
func (fakeBackend) Probe(context.Context) error { return nil }

type recorder struct {
	mu      sync.Mutex
	reloads [][]string
	builds  atomic.Int64
}

func (r *recorder) build(s *secretstore.Store) (secretstore.Backend, error) {
	r.builds.Add(1)
	return fakeBackend{name: s.Name}, nil
}

func (r *recorder) onReload(changed []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloads = append(r.reloads, changed)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reloads)
}

func (r *recorder) last() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reloads) == 0 {
		return nil
	}
	return r.reloads[len(r.reloads)-1]
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const twoEnvStores = "version: 1\nstores:\n  - { name: a, type: env, allowed_paths: [\"*\"], env: { prefix: A_ } }\n  - { name: b, type: env, allowed_paths: [\"*\"], env: { prefix: B_ } }\n"

func TestOpenRefusesSaaSAndBrokenFiles(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "stores.yaml")
	writeFile(t, path, twoEnvStores)
	r := &recorder{}
	if _, err := localfile.Open(path, r.build, localfile.Options{DeploymentType: "SaaS"}); !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("saas plane: %v", err)
	}
	if _, err := localfile.Open(filepath.Join(t.TempDir(), "missing.yaml"), r.build, localfile.Options{}); !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("missing file: %v", err)
	}
	writeFile(t, path, "version: 1\nstores: [")
	if _, err := localfile.Open(path, r.build, localfile.Options{}); !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("broken file: %v", err)
	}
}

func TestReload(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "stores.yaml")
	writeFile(t, path, twoEnvStores)
	r := &recorder{}
	c, err := localfile.Open(path, r.build, localfile.Options{Logger: quietLogger(), OnReload: r.onReload})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(c.Stores()); got != 2 || r.builds.Load() != 2 {
		t.Fatalf("stores %d, builds %d", got, r.builds.Load())
	}
	_, backendA, _ := c.Get("A")

	writeFile(t, path, "version: 1\nstores:\n  - { name: a, type: env, allowed_paths: [\"*\"], env: { prefix: A_ } }\n  - { name: c, type: env, allowed_paths: [\"*\"], env: { prefix: C_ } }\n")
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := r.last(); strings.Join(got, ",") != "b,c" {
		t.Fatalf("changed = %v, want [b c] (a unchanged, b removed, c added)", got)
	}
	if _, again, _ := c.Get("a"); again != backendA || r.builds.Load() != 3 {
		t.Fatalf("an unchanged store must keep its backend (builds %d)", r.builds.Load())
	}

	writeFile(t, path, "version: 1\nstores: [ {")
	if err := c.Reload(); err == nil {
		t.Fatal("broken file reloaded")
	}
	if c.LoadError() == nil || len(c.Stores()) != 2 {
		t.Fatalf("a broken reload must keep the stores and report: err %v, stores %d", c.LoadError(), len(c.Stores()))
	}
	if _, _, ok := c.Get("c"); !ok {
		t.Fatal("previous store lost")
	}

	writeFile(t, path, "version: 1\nstores:\n  - { name: a, type: env, allowed_paths: [\"*\"], env: { prefix: Z_ } }\n")
	if err := c.Reload(); err != nil {
		t.Fatal(err)
	}
	if c.LoadError() != nil {
		t.Fatal("a good reload must clear the load error")
	}
	if got := r.last(); strings.Join(got, ",") != "a,c" {
		t.Fatalf("changed = %v, want [a c]", got)
	}
}

// TestWatchFollowsConfigMapUpdates swaps the ..data symlink the way the
// kubelet publishes a new ConfigMap version.
func TestWatchFollowsConfigMapUpdates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	publish := func(version, body string) {
		t.Helper()
		versionDir := filepath.Join(dir, version)
		if err := os.Mkdir(versionDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(versionDir, "stores.yaml"), body)
		tmp := filepath.Join(dir, "..data_tmp")
		if err := os.Symlink(version, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	publish("..v1", twoEnvStores)
	if err := os.Symlink(filepath.Join("..data", "stores.yaml"), filepath.Join(dir, "stores.yaml")); err != nil {
		t.Fatal(err)
	}

	r := &recorder{}
	c, err := localfile.Open(filepath.Join(dir, "stores.yaml"), r.build, localfile.Options{Logger: quietLogger(), OnReload: r.onReload})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Watch(ctx) }()
	time.Sleep(100 * time.Millisecond)

	for i, body := range []string{
		"version: 1\nstores:\n  - { name: a, type: env, allowed_paths: [\"*\"], env: { prefix: A_ } }\n",
		"version: 1\nstores:\n  - { name: a, type: env, allowed_paths: [\"*\"], env: { prefix: Q_ } }\n",
	} {
		publish("..v"+string(rune('2'+i)), body)
		deadline := time.Now().Add(3 * time.Second)
		for r.count() < i+1 {
			if time.Now().After(deadline) {
				t.Fatalf("update %d was not picked up", i+1)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watch: %v", err)
	}
	store, _, _ := c.Get("a")
	if prefix := store.Config.(*secretstore.EnvConfig).Prefix; prefix != "Q_" {
		t.Fatalf("prefix = %q after the second update", prefix)
	}
}
