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

package modules

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

func secretStoresFor(t *testing.T, cfg config.SecretStoresConfig, deployment string) (*SecretStores, error) {
	t.Helper()
	c := &config.Config{SecretStores: cfg}
	c.ConfigSync.DeploymentType = deployment
	return provideSecretStores(secretStoresParams{
		Config:  c,
		Manager: cache.NewTTLMapManager(time.Hour),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestSecretStoresWithoutAFileOnlyMaterializes(t *testing.T) {
	t.Parallel()
	for _, cfg := range []config.SecretStoresConfig{
		{},
		{Enabled: true, Gateways: secretstore.EligibilityHybrid},
	} {
		s, err := secretStoresFor(t, cfg, "saas")
		if err != nil {
			t.Fatal(err)
		}
		if s.Catalog != nil || s.Cache != nil || s.Materializer == nil {
			t.Fatalf("stores = %+v", s)
		}
		s.Start()
		s.Stop()
	}
}

func TestSecretStoresLoadTheFileAndRun(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "stores.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nstores:\n  - { name: env, type: env, allowed_paths: [\"*\"], env: { prefix: TG_SECRET_ } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.SecretStoresConfig{
		Enabled: true, Gateways: secretstore.EligibilityAll, File: path,
		FetchTimeout: time.Second, RefreshInterval: time.Second, ProbeInterval: time.Second,
	}
	s, err := secretStoresFor(t, cfg, "self-hosted")
	if err != nil {
		t.Fatal(err)
	}
	if s.Catalog == nil || s.Cache == nil {
		t.Fatal("a plane with a store file must load it")
	}
	s.Start()
	s.Stop()

	if _, err := secretStoresFor(t, cfg, "saas"); err == nil {
		t.Fatal("a saas plane must refuse a store file")
	}
}
