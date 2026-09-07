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

package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

type fakeStreamVault struct {
	creds []*vaultdomain.Credential
}

func (f *fakeStreamVault) Upsert(context.Context, *vaultdomain.Credential) error { return nil }
func (f *fakeStreamVault) Find(context.Context, ids.GatewayID, string, string) (*vaultdomain.Credential, error) {
	return nil, vaultdomain.ErrNotFound
}
func (f *fakeStreamVault) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return f.creds, nil
}
func (f *fakeStreamVault) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

func forwardedRegistry(t *testing.T, gw ids.GatewayID, name, provider string) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
		URL: "https://up.example.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     provider,
			Registration: registrydomain.RegistrationAuto,
		},
	})
	if err != nil {
		t.Fatalf("registry %q: %v", name, err)
	}
	return reg
}

// The stream's routable consumer is frozen when the stream opens. A server
// installed later in the same session (here: Notion) is therefore absent from
// that frozen registry set. connectionWatchSnapshot must still report a
// credential connected for it, otherwise no tools/list_changed is pushed and the
// client keeps a tool list that never gains the just-connected server — the
// synchronisation bug this test guards against.
func TestConnectionWatchSnapshot_ReportsCredentialForServerInstalledAfterStreamOpened(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	vault := &fakeStreamVault{creds: []*vaultdomain.Credential{
		{GatewayID: gw, PrincipalSub: "ana", Provider: "com.notion/mcp", UpdatedAt: now},
	}}
	h := NewHandler(nil, nil, vault)

	// The frozen consumer only knows Linear; Notion was installed after the stream
	// opened and is not in this registry set.
	rc := &appconsumer.RoutableConsumer{
		Consumer:   &consumerdomain.Consumer{GatewayID: gw, Slug: "dev"},
		Registries: []*registrydomain.Registry{forwardedRegistry(t, gw, "linear-mcp", "com.linear/mcp")},
	}
	principal := &identity.Principal{Subject: "ana"}

	watch := h.connectionWatchSnapshot(context.Background(), rc, principal)
	if len(watch) != 1 || !strings.HasPrefix(watch[0], "cx:com.notion/mcp@") {
		t.Fatalf("watch snapshot must report the Notion credential regardless of the frozen registry set, got %v", watch)
	}

	// The frozen-registry-filtered snapshot drops it — that is exactly why the
	// stream must not use it, and why the two functions must stay distinct.
	if filtered := h.connectionSnapshot(context.Background(), rc, principal); len(filtered) != 0 {
		t.Fatalf("connectionSnapshot filters by the frozen forwarded set and must drop the Notion credential, got %v", filtered)
	}

	// A reconnect (new UpdatedAt) changes the watch string, so the polling stream
	// sees a change and pushes tools/list_changed.
	vault.creds[0].UpdatedAt = now.Add(time.Minute)
	if next := h.connectionWatchSnapshot(context.Background(), rc, principal); next[0] == watch[0] {
		t.Fatal("a reconnected credential must change the watch snapshot string")
	}
}
