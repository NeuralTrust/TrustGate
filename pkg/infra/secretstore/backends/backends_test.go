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

package backends_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/awssm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/backends"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/envstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/filestore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/gcpsm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/hashicorp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/localfile"
)

func TestFactoryBuildsEveryPhase1Type(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	path := filepath.Join(t.TempDir(), "stores.yaml")
	raw := `version: 1
stores:
  - { name: v, type: hashicorp_vault, allowed_paths: ["*"], hashicorp_vault: { address: "https://vault:8200", auth: { method: kubernetes, role: r } } }
  - { name: a, type: aws_secrets_manager, allowed_paths: ["*"], aws_secrets_manager: { region: eu-west-1 } }
  - { name: g, type: gcp_secret_manager, allowed_paths: ["*"], gcp_secret_manager: { project_id: p } }
  - { name: f, type: file, allowed_paths: ["*"], file: { root: /var/run/secrets } }
  - { name: e, type: env, allowed_paths: ["*"], env: { prefix: TG_ } }
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := localfile.Open(path, backends.Factory(context.Background()), localfile.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := map[string]any{
		"v": &hashicorp.Backend{}, "a": &awssm.Backend{}, "g": &gcpsm.Backend{},
		"f": &filestore.Backend{}, "e": &envstore.Backend{},
	}
	for name, typ := range want {
		_, b, ok := c.Get(name)
		if !ok {
			t.Fatalf("store %s missing", name)
		}
		if got, wantT := backendKind(b), backendKind(typ); got != wantT {
			t.Errorf("store %s backend = %s, want %s", name, got, wantT)
		}
	}
}

func backendKind(v any) string {
	switch v.(type) {
	case *hashicorp.Backend:
		return "hashicorp"
	case *awssm.Backend:
		return "awssm"
	case *gcpsm.Backend:
		return "gcpsm"
	case *filestore.Backend:
		return "filestore"
	case *envstore.Backend:
		return "envstore"
	default:
		return "unknown"
	}
}

func TestFactoryRefusesUnsupportedTypes(t *testing.T) {
	t.Parallel()
	_, err := backends.Factory(context.Background())(&secretstore.Store{Name: "z", Type: secretstore.TypeAzureKeyVault})
	if !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("azure: %v", err)
	}
	_, err = backends.Factory(context.Background())(&secretstore.Store{
		Name: "v", Type: secretstore.TypeHashiCorpVault,
		Config: &secretstore.HashiCorpVaultConfig{Address: "https://v", CACertFile: "/missing/ca.crt"},
	})
	if !errors.Is(err, secretstore.ErrInvalidStore) {
		t.Fatalf("missing CA file: %v", err)
	}
}
