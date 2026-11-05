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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakeEveryoneRepo struct {
	items   map[ids.GatewayID]*storeaccessdomain.Everyone
	deleted []ids.GatewayID
}

func (f *fakeEveryoneRepo) GetEveryone(_ context.Context, gw ids.GatewayID) (*storeaccessdomain.Everyone, error) {
	return f.items[gw], nil
}

func (f *fakeEveryoneRepo) ListEveryone(context.Context, int, int) ([]*storeaccessdomain.Everyone, int, error) {
	out := make([]*storeaccessdomain.Everyone, 0, len(f.items))
	for _, e := range f.items {
		out = append(out, e)
	}
	return out, len(out), nil
}

func (f *fakeEveryoneRepo) UpsertEveryone(_ context.Context, e *storeaccessdomain.Everyone) error {
	if f.items == nil {
		f.items = map[ids.GatewayID]*storeaccessdomain.Everyone{}
	}
	f.items[e.GatewayID] = e
	return nil
}

func (f *fakeEveryoneRepo) DeleteEveryone(_ context.Context, gw ids.GatewayID) error {
	f.deleted = append(f.deleted, gw)
	delete(f.items, gw)
	return nil
}

func (f *fakeEveryoneRepo) PruneRegistry(ctx context.Context, gw ids.GatewayID, registryID ids.RegistryID) error {
	e := f.items[gw]
	if e == nil {
		return nil
	}
	pruned, changed := e.WithoutRegistry(registryID)
	if !changed {
		return nil
	}
	if pruned.Validate() != nil {
		return f.DeleteEveryone(ctx, gw)
	}
	return f.UpsertEveryone(ctx, pruned)
}

func newEveryoneServiceT(t *testing.T, repo storeaccessdomain.EveryoneRepository, regs *fakeRegistries, sig *countingSignaler) EveryoneService {
	t.Helper()
	svc, err := NewEveryoneService(repo, regs, testCatalog(), sig)
	if err != nil {
		t.Fatalf("NewEveryoneService: %v", err)
	}
	return svc
}

func TestEveryoneService_SetWritesReadsAndSignals(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	repo := &fakeEveryoneRepo{}
	sig := &countingSignaler{}
	svc := newEveryoneServiceT(t, repo, &fakeRegistries{}, sig)

	e, err := svc.Set(context.Background(), SetEveryoneRequest{
		GatewayID:      gw,
		Mode:           " Curated ",
		Grants:         []storeaccessdomain.EveryoneGrant{{CatalogCode: "github"}, {CatalogCode: "github"}},
		ExcludedGroups: []string{" Contractors ", "Contractors"},
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if e.Mode != "curated" || len(e.Grants) != 1 || len(e.ExcludedGroups) != 1 || e.ExcludedGroups[0] != "Contractors" || sig.n != 1 {
		t.Fatalf("expected a normalised write and one signal, got %+v signals=%d", e, sig.n)
	}
	got, err := svc.GetEveryone(context.Background(), gw)
	if err != nil || got == nil || got.Mode != "curated" {
		t.Fatalf("GetEveryone: %+v / %v", got, err)
	}
}

func TestEveryoneService_EmptyModeRemoves(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	repo := &fakeEveryoneRepo{items: map[ids.GatewayID]*storeaccessdomain.Everyone{gw: {GatewayID: gw, Mode: "open"}}}
	sig := &countingSignaler{}
	svc := newEveryoneServiceT(t, repo, &fakeRegistries{}, sig)

	e, err := svc.Set(context.Background(), SetEveryoneRequest{GatewayID: gw})
	if err != nil || e != nil {
		t.Fatalf("removal must return nil, got %+v / %v", e, err)
	}
	if len(repo.items) != 0 || len(repo.deleted) != 1 || sig.n != 1 {
		t.Fatalf("removal must delete and signal, items=%d deleted=%d signals=%d", len(repo.items), len(repo.deleted), sig.n)
	}
	if got, _ := svc.GetEveryone(context.Background(), gw); got != nil {
		t.Fatalf("a removed object must read as nil, got %+v", got)
	}
}

func TestEveryoneService_RejectsInvalidObjects(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	github := shelfRegistry("github")
	svc := newEveryoneServiceT(t, &fakeEveryoneRepo{}, &fakeRegistries{items: []*registrydomain.Registry{github}}, &countingSignaler{})

	cases := []struct {
		name string
		in   SetEveryoneRequest
		want error
	}{
		{"none", SetEveryoneRequest{GatewayID: gw, Mode: "none"}, commonerrors.ErrValidation},
		{"curated without grants", SetEveryoneRequest{GatewayID: gw, Mode: "curated"}, commonerrors.ErrValidation},
		{"unknown server", SetEveryoneRequest{GatewayID: gw, Mode: "curated", Grants: []storeaccessdomain.EveryoneGrant{{CatalogCode: "nope"}}}, commonerrors.ErrValidation},
		{"foreign instance", SetEveryoneRequest{GatewayID: gw, Mode: "curated", Grants: []storeaccessdomain.EveryoneGrant{{CatalogCode: "snowflake", RegistryID: github.ID}}}, ErrUnknownInstance},
		{"removal without gateway", SetEveryoneRequest{}, commonerrors.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.Set(context.Background(), tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}

	e, err := svc.Set(context.Background(), SetEveryoneRequest{GatewayID: gw, Mode: "curated", Grants: []storeaccessdomain.EveryoneGrant{{CatalogCode: "github", RegistryID: github.ID}}})
	if err != nil || !e.Grants[0].IsInstance() {
		t.Fatalf("a valid instance grant must be written, got %+v / %v", e, err)
	}
}

func TestNewEveryoneServiceRejectsNilDeps(t *testing.T) {
	if _, err := NewEveryoneService(nil, &fakeRegistries{}, testCatalog(), nil); err == nil {
		t.Fatal("nil repo must error")
	}
}
