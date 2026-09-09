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

package store

import (
	"context"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// materializingEnsurer appends the catalog registry to the shared fake lister,
// standing in for the control-plane Creator round trip.
type materializingEnsurer struct {
	catalog fakeCatalog
	regs    *fakeRegistries
	calls   int
}

func (e *materializingEnsurer) Ensure(_ context.Context, gatewayID ids.GatewayID, code string) error {
	e.calls++
	entry, _ := e.catalog.GetByCode(code)
	reg, err := catalogRegistry(entry, gatewayID)
	if err != nil {
		return err
	}
	e.regs.items = append(e.regs.items, reg)
	return nil
}

func newMaterializerFixture(t *testing.T, entries ...catalogdomain.MCPServer) (CatalogMaterializer, *fakeRegistries, *materializingEnsurer) {
	t.Helper()
	catalog := fakeCatalog{entries: map[string]catalogdomain.MCPServer{}}
	for _, e := range entries {
		catalog.entries[e.Code] = e
	}
	regs := &fakeRegistries{}
	ensurer := &materializingEnsurer{catalog: catalog, regs: regs}
	m, err := NewCatalogMaterializer(catalog, regs, ensurer)
	if err != nil {
		t.Fatalf("NewCatalogMaterializer: %v", err)
	}
	return m, regs, ensurer
}

func TestCatalogMaterializer_SelfServiceCreatesStoreOriginRegistry(t *testing.T) {
	notion := catalogdomain.MCPServer{
		Code:        "com.notion/mcp",
		DisplayName: "Notion",
		URL:         "https://mcp.notion.com/mcp",
		AuthHint:    "oauth",
		AuthMethods: []string{"oauth"},
		SelfService: true,
		OAuth:       &catalogdomain.MCPOAuth{Registration: "auto"},
	}
	m, regs, ensurer := newMaterializerFixture(t, notion)
	gw := ids.GatewayID{}

	reg, err := m.Materialize(context.Background(), gw, "com.notion/mcp")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if reg == nil || reg.MCPTarget == nil {
		t.Fatalf("expected a registry with an mcp target, got %+v", reg)
	}
	if reg.MCPTarget.Origin != registrydomain.MCPOriginStore {
		t.Fatalf("origin = %q, want %q", reg.MCPTarget.Origin, registrydomain.MCPOriginStore)
	}
	if reg.MCPTarget.Code != "com.notion/mcp" {
		t.Fatalf("code = %q", reg.MCPTarget.Code)
	}
	if len(regs.items) != 1 || ensurer.calls != 1 {
		t.Fatalf("expected one materialised registry, got %d (ensure calls %d)", len(regs.items), ensurer.calls)
	}

	// Idempotent: a second call returns the same registry without re-ensuring.
	again, err := m.Materialize(context.Background(), gw, "com.notion/mcp")
	if err != nil {
		t.Fatalf("second Materialize: %v", err)
	}
	if again.ID != reg.ID || ensurer.calls != 1 {
		t.Fatalf("expected the existing registry back (ensure calls %d)", ensurer.calls)
	}
}

func TestCatalogMaterializer_NeedsAdminSetupIsConflict(t *testing.T) {
	apiKeyOnly := catalogdomain.MCPServer{
		Code:        "com.acme/mcp",
		DisplayName: "Acme",
		URL:         "https://mcp.acme.com/mcp",
		AuthHint:    "static",
		AuthMethods: []string{"static"},
		AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "X-API-Key", Required: true, Secret: true}},
	}
	m, regs, ensurer := newMaterializerFixture(t, apiKeyOnly)

	_, err := m.Materialize(context.Background(), ids.GatewayID{}, "com.acme/mcp")
	if !errors.Is(err, ErrNeedsAdminSetup) || !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("expected ErrNeedsAdminSetup (conflict), got %v", err)
	}
	if len(regs.items) != 0 || ensurer.calls != 0 {
		t.Fatalf("nothing should be materialised, got %d registries / %d ensure calls", len(regs.items), ensurer.calls)
	}
}

func TestCatalogMaterializer_ExistingAdminRegistryWins(t *testing.T) {
	apiKeyOnly := catalogdomain.MCPServer{
		Code:        "com.acme/mcp",
		DisplayName: "Acme",
		URL:         "https://mcp.acme.com/mcp",
		AuthHint:    "static",
		AuthMethods: []string{"static"},
		AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "X-API-Key", Required: true, Secret: true}},
	}
	m, regs, ensurer := newMaterializerFixture(t, apiKeyOnly)
	id, _ := ids.NewV7[ids.RegistryKind]()
	regs.items = append(regs.items, &registrydomain.Registry{
		ID:        id,
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.acme/mcp", URL: "https://mcp.acme.com/mcp"},
	})

	reg, err := m.Materialize(context.Background(), ids.GatewayID{}, "com.acme/mcp")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if reg.ID != id || ensurer.calls != 0 {
		t.Fatalf("expected the admin registry back without ensuring, got %v (calls %d)", reg.ID, ensurer.calls)
	}
}

func TestCatalogMaterializer_UnknownCodeIsNotFound(t *testing.T) {
	m, _, _ := newMaterializerFixture(t)
	_, err := m.Materialize(context.Background(), ids.GatewayID{}, "nope")
	if !errors.Is(err, ErrCatalogEntryNotFound) || !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	_, err = m.Materialize(context.Background(), ids.GatewayID{}, "  ")
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected validation error for blank code, got %v", err)
	}
}
