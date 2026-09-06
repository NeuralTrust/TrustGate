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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storegrantdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storegrant"
)

// fakeGrantRepo is the control-plane repository the service writes through.
type fakeGrantRepo struct {
	fakeGrants
	deleted []string
}

func (f *fakeGrantRepo) List(context.Context, int, int) ([]*storegrantdomain.Grant, int, error) {
	return f.items, len(f.items), nil
}

func (f *fakeGrantRepo) Upsert(ctx context.Context, g *storegrantdomain.Grant) error {
	if g.IsEmpty() {
		return f.Delete(ctx, g.GatewayID, g.CatalogCode, g.RegistryID)
	}
	return f.fakeGrants.Upsert(ctx, g)
}

func (f *fakeGrantRepo) Delete(_ context.Context, _ ids.GatewayID, code string, registryID ids.RegistryID) error {
	f.deleted = append(f.deleted, code+"/"+registryID.String())
	kept := f.items[:0]
	for _, g := range f.items {
		if g.CatalogCode != code || g.RegistryID != registryID {
			kept = append(kept, g)
		}
	}
	f.items = kept
	return nil
}

func (f *fakeGrantRepo) DeleteByRegistry(context.Context, ids.GatewayID, ids.RegistryID) error {
	return nil
}

type countingSignaler struct{ n int }

func (c *countingSignaler) Signal(context.Context) { c.n++ }

func newGrantServiceT(t *testing.T, repo *fakeGrantRepo, regs *fakeRegistries, sig *countingSignaler) GrantService {
	t.Helper()
	svc, err := NewGrantService(repo, regs, testCatalog(), sig)
	if err != nil {
		t.Fatalf("NewGrantService: %v", err)
	}
	return svc
}

func TestGrantService_SetCodeGrantWritesAndSignals(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	repo := &fakeGrantRepo{}
	sig := &countingSignaler{}
	svc := newGrantServiceT(t, repo, &fakeRegistries{}, sig)

	g, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "github", Groups: []string{"eng"}, Users: []string{"ana"}})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if g.IsInstance() || len(repo.upserts) != 1 || sig.n != 1 {
		t.Fatalf("expected one code-level write and one signal, got %+v upserts=%d signals=%d", g, len(repo.upserts), sig.n)
	}
	// The whole catalog is grantable: no registry had to exist.
	got, _ := svc.ListByGateway(context.Background(), gw)
	if len(got) != 1 || got[0].CatalogCode != "github" {
		t.Fatalf("grant must be listed, got %+v", got)
	}
}

func TestGrantService_SetEmptyClearsGrant(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	repo := &fakeGrantRepo{fakeGrants: fakeGrants{items: []*storegrantdomain.Grant{codeGrant(gw, "github", nil, []string{"ana"})}}}
	svc := newGrantServiceT(t, repo, &fakeRegistries{}, &countingSignaler{})
	if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "github"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(repo.items) != 0 || len(repo.deleted) != 1 {
		t.Fatalf("an empty grant must delete the row, items=%d deleted=%v", len(repo.items), repo.deleted)
	}
}

func TestGrantService_RejectsUnknownCodeAndForeignInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	github := shelfRegistry("github")
	svc := newGrantServiceT(t, &fakeGrantRepo{}, &fakeRegistries{items: []*registrydomain.Registry{github}}, &countingSignaler{})

	if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "nope", Users: []string{"ana"}}); !errors.Is(err, ErrCatalogEntryNotFound) {
		t.Fatalf("unknown code: expected ErrCatalogEntryNotFound, got %v", err)
	}
	// An instance grant must name a registry of THIS code.
	if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "snowflake", RegistryID: github.ID, Users: []string{"ana"}}); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("foreign instance: expected ErrUnknownInstance, got %v", err)
	}
	if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "github", RegistryID: ids.New[ids.RegistryKind](), Users: []string{"ana"}}); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("unknown instance: expected ErrUnknownInstance, got %v", err)
	}
	g, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: "github", RegistryID: github.ID, Users: []string{"ana"}})
	if err != nil || !g.IsInstance() {
		t.Fatalf("a valid instance grant must be written, got %+v / %v", g, err)
	}
}

func TestNewGrantServiceRejectsNilDeps(t *testing.T) {
	if _, err := NewGrantService(nil, &fakeRegistries{}, testCatalog(), nil); err == nil {
		t.Fatal("nil repo must error")
	}
}
