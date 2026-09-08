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

package vault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
)

// memVault is an in-memory stand-in for one of the two credential stores.
type memVault struct {
	creds map[string]*domain.Credential
	err   error
}

func newMemVault(creds ...*domain.Credential) *memVault {
	m := &memVault{creds: map[string]*domain.Credential{}}
	for _, cred := range creds {
		m.creds[cred.Provider] = cred
	}
	return m
}

func (m *memVault) Upsert(_ context.Context, c *domain.Credential) error {
	if m.err != nil {
		return m.err
	}
	m.creds[c.Provider] = c
	return nil
}

func (m *memVault) Find(_ context.Context, _ ids.GatewayID, _, provider string) (*domain.Credential, error) {
	if m.err != nil {
		return nil, m.err
	}
	if cred, ok := m.creds[provider]; ok {
		return cred, nil
	}
	return nil, domain.ErrNotFound
}

func (m *memVault) ListByPrincipal(_ context.Context, _ ids.GatewayID, _ string) ([]*domain.Credential, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]*domain.Credential, 0, len(m.creds))
	for _, cred := range m.creds {
		out = append(out, cred)
	}
	return out, nil
}

func (m *memVault) Delete(_ context.Context, _ ids.GatewayID, _, provider string) error {
	if m.err != nil {
		return m.err
	}
	if _, ok := m.creds[provider]; !ok {
		return domain.ErrNotFound
	}
	delete(m.creds, provider)
	return nil
}

func cred(provider, account string) *domain.Credential {
	return &domain.Credential{Provider: provider, AccountRef: account}
}

func TestFallbackRepository(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	ctx := context.Background()

	t.Run("reads a credential the data plane wrote to the other store", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault()
		fallback := newMemVault(cred("app.linear/mcp", "victor@corp.com"))
		repo := vaultrepo.NewFallbackRepository(primary, fallback)

		got, err := repo.Find(ctx, gw, "user-1", "app.linear/mcp")
		if err != nil {
			t.Fatalf("Find: %v", err)
		}
		if got.AccountRef != "victor@corp.com" {
			t.Fatalf("account = %q", got.AccountRef)
		}
	})

	t.Run("prefers the primary and reports its undecryptable answer", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault(cred("github", "primary"))
		fallback := newMemVault(cred("github", "fallback"))
		repo := vaultrepo.NewFallbackRepository(primary, fallback)

		got, err := repo.Find(ctx, gw, "user-1", "github")
		if err != nil || got.AccountRef != "primary" {
			t.Fatalf("Find = %v, %v; want the primary's credential", got, err)
		}

		// A credential written under a rotated key is still an answer about that
		// person: falling through would report them as never connected.
		primary.err = domain.ErrUndecryptable
		if _, err := repo.Find(ctx, gw, "user-1", "github"); !errors.Is(err, domain.ErrUndecryptable) {
			t.Fatalf("error = %v, want ErrUndecryptable", err)
		}
	})

	t.Run("reports not found only when neither store has it", func(t *testing.T) {
		t.Parallel()
		repo := vaultrepo.NewFallbackRepository(newMemVault(), newMemVault())
		if _, err := repo.Find(ctx, gw, "user-1", "github"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("lists both stores once per provider", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault(cred("github", "primary"))
		fallback := newMemVault(cred("github", "shadow"), cred("app.linear/mcp", "victor@corp.com"))
		repo := vaultrepo.NewFallbackRepository(primary, fallback)

		creds, err := repo.ListByPrincipal(ctx, gw, "user-1")
		if err != nil {
			t.Fatalf("ListByPrincipal: %v", err)
		}
		if len(creds) != 2 {
			t.Fatalf("got %d credentials, want 2 (github deduped, linear included)", len(creds))
		}
		for _, c := range creds {
			if c.Provider == "github" && c.AccountRef != "primary" {
				t.Fatalf("github account = %q, want the primary's", c.AccountRef)
			}
		}
	})

	t.Run("writes to the primary only", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault()
		fallback := newMemVault()
		repo := vaultrepo.NewFallbackRepository(primary, fallback)

		if err := repo.Upsert(ctx, cred("github", "octocat")); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if _, ok := primary.creds["github"]; !ok {
			t.Fatal("the credential must be durable on the primary")
		}
		if _, ok := fallback.creds["github"]; ok {
			t.Fatal("the fallback is a read path, not a second copy")
		}
	})

	// Revoking from the control plane must not leave the data plane's copy live.
	t.Run("deletes from both stores", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault(cred("github", "primary"))
		fallback := newMemVault(cred("github", "shadow"))
		repo := vaultrepo.NewFallbackRepository(primary, fallback)

		if err := repo.Delete(ctx, gw, "user-1", "github"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if len(primary.creds) != 0 || len(fallback.creds) != 0 {
			t.Fatalf("primary=%d fallback=%d, want both empty", len(primary.creds), len(fallback.creds))
		}
	})

	t.Run("deleting what only one store holds succeeds", func(t *testing.T) {
		t.Parallel()
		repo := vaultrepo.NewFallbackRepository(newMemVault(), newMemVault(cred("github", "shadow")))
		if err := repo.Delete(ctx, gw, "user-1", "github"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})

	t.Run("deleting what neither holds is not found", func(t *testing.T) {
		t.Parallel()
		repo := vaultrepo.NewFallbackRepository(newMemVault(), newMemVault())
		if err := repo.Delete(ctx, gw, "user-1", "github"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("a single store carries no wrapper", func(t *testing.T) {
		t.Parallel()
		primary := newMemVault()
		if repo := vaultrepo.NewFallbackRepository(primary, nil); repo != domain.Repository(primary) {
			t.Fatal("a nil fallback must return the primary unchanged")
		}
	})
}
