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
	"fmt"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type pagedRegistryLister struct {
	items []*registrydomain.Registry
	calls int
}

func (l *pagedRegistryLister) List(_ context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	l.calls++
	start := (filter.Page - 1) * filter.Size
	if start >= len(l.items) {
		return nil, len(l.items), nil
	}
	end := min(start+filter.Size, len(l.items))
	return l.items[start:end], len(l.items), nil
}

type indexedRegistryLister struct {
	items     []*registrydomain.Registry
	listCalls int
	codeCalls int
	idCalls   int
}

func (l *indexedRegistryLister) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	l.listCalls++
	return nil, 0, nil
}

func (l *indexedRegistryLister) ListByGateway(context.Context, ids.GatewayID) ([]*registrydomain.Registry, error) {
	return l.items, nil
}

func (l *indexedRegistryLister) ListByGatewayAndCatalogCode(context.Context, ids.GatewayID, string) ([]*registrydomain.Registry, error) {
	l.codeCalls++
	return l.items, nil
}

func (l *indexedRegistryLister) ListByGatewayAndIDs(context.Context, ids.GatewayID, []ids.RegistryID) ([]*registrydomain.Registry, error) {
	l.idCalls++
	return l.items, nil
}

func TestListRegistriesByGatewayPaginatesWithoutTruncation(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	items := make([]*registrydomain.Registry, 0, 251)
	for n := 0; n < 251; n++ {
		items = append(items, &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, Name: fmt.Sprint(n)})
	}
	lister := &pagedRegistryLister{items: items}

	got, err := listRegistriesByGateway(context.Background(), lister, gatewayID)
	if err != nil {
		t.Fatalf("list registries: %v", err)
	}
	if len(got) != len(items) {
		t.Fatalf("listed %d registries, want %d", len(got), len(items))
	}
	if lister.calls != 3 {
		t.Fatalf("List called %d times, want 3", lister.calls)
	}
}

func TestFindRegistriesByCodeUsesIndexedReader(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	newer := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, MCPTarget: &registrydomain.MCPTarget{Code: "github"}, CreatedAt: time.Unix(2, 0)}
	older := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, MCPTarget: &registrydomain.MCPTarget{Code: "github"}, CreatedAt: time.Unix(1, 0)}
	want := []*registrydomain.Registry{newer, older}
	lister := &indexedRegistryLister{items: want}

	got, err := findRegistriesByCode(context.Background(), lister, gatewayID, "github")
	if err != nil {
		t.Fatalf("find registries: %v", err)
	}
	if len(got) != 2 || got[0] != older || got[1] != newer {
		t.Fatalf("find registries = %#v", got)
	}
	if lister.items[0] != newer || lister.items[1] != older {
		t.Fatal("indexed snapshot order was mutated")
	}
	if lister.codeCalls != 1 || lister.listCalls != 0 {
		t.Fatalf("indexed calls = %d, generic calls = %d", lister.codeCalls, lister.listCalls)
	}
}

func TestListRegistriesForInstallsUsesNarrowIndexes(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	lister := &indexedRegistryLister{items: []*registrydomain.Registry{{
		ID: registryID, GatewayID: gatewayID, MCPTarget: &registrydomain.MCPTarget{Code: "github"},
	}}}
	installs := []*installationdomain.Installation{
		{RegistryID: registryID, CatalogCode: "github"},
		{CatalogCode: "gitlab"},
		{CatalogCode: "gitlab"},
	}

	got, err := listRegistriesForInstalls(context.Background(), lister, gatewayID, installs)
	if err != nil {
		t.Fatalf("list registries for installs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("listed %d registries, want one unique registry", len(got))
	}
	if lister.idCalls != 1 || lister.codeCalls != 1 || lister.listCalls != 0 {
		t.Fatalf("id calls = %d, code calls = %d, generic calls = %d", lister.idCalls, lister.codeCalls, lister.listCalls)
	}
}
