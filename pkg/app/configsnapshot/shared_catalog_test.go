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

package configsnapshot_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
)

type mutableCatalog struct {
	catalog fakeCatalog
}

func (m *mutableCatalog) ListProviders(ctx context.Context) ([]catalogdomain.Provider, error) {
	return m.catalog.ListProviders(ctx)
}

func (m *mutableCatalog) ListModelsByProviderCode(ctx context.Context, code string) ([]catalogdomain.Model, error) {
	return m.catalog.ListModelsByProviderCode(ctx, code)
}

func sharedCatalogFixture(models int) fakeCatalog {
	openai := make([]catalogdomain.Model, models)
	for i := range openai {
		openai[i] = catalogdomain.Model{Slug: fmt.Sprintf("model-%04d", i), DisplayName: "Model with a reasonably long display name"}
	}
	return fakeCatalog{
		providers:    []catalogdomain.Provider{{Code: "openai"}, {Code: "anthropic"}},
		modelsByCode: map[string][]catalogdomain.Model{"openai": openai, "anthropic": {{Slug: "claude"}}},
	}
}

func newSharedCatalogDispatcher(gateways appsnapshot.GatewayReader, catalog appsnapshot.CatalogReader) (*appsnapshot.Dispatcher, *appsnapshot.Holder, *appsnapshot.Compiler) {
	compiler := appsnapshot.NewCompiler(
		gateways,
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		catalog,
		nil,
	)
	holder := appsnapshot.NewHolder()
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})
	return d, holder, compiler
}

func TestDispatch_ScopedSnapshotIsTenantBytesThenSharedCatalog(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA, Slug: "a"}, {ID: gwB, Slug: "b"}}}
	d, holder, compiler := newSharedCatalogDispatcher(gateways, sharedCatalogFixture(20))
	codec := infrasnapshot.NewCodec()

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	_, scoped, catalog, err := compiler.CompileAll(context.Background())
	if err != nil {
		t.Fatalf("CompileAll: %v", err)
	}
	catalogRaw, err := codec.Encode(catalog)
	if err != nil {
		t.Fatalf("encode catalog: %v", err)
	}
	var catalogs [][]byte
	for _, gw := range []string{gwA.String(), gwB.String()} {
		tenantRaw, err := codec.Encode(scoped[gw])
		if err != nil {
			t.Fatalf("encode %s: %v", gw, err)
		}
		want := append(append([]byte{}, tenantRaw...), catalogRaw...)

		raw, version, ok := holder.SnapshotFor(gw)
		if !ok || !bytes.Equal(raw, want) || version != codec.Version(want) {
			t.Fatalf("scope %s must serve tenant bytes then catalog bytes, versioned by their sha256; ok=%v equal=%v", gw, ok, bytes.Equal(raw, want))
		}
		parts, partsVersion, ok := holder.SnapshotPartsFor(gw)
		if !ok || partsVersion != version || len(parts) != 2 || !bytes.Equal(bytes.Join(parts, nil), want) {
			t.Fatalf("scope %s parts must concatenate to the served snapshot; got %d parts", gw, len(parts))
		}
		catalogs = append(catalogs, parts[1])
	}
	if &catalogs[0][0] != &catalogs[1][0] {
		t.Fatalf("every scope of a compile must share one catalog slice")
	}
}

func TestDispatch_UnchangedScopeKeepsItsHeldBytes(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA, Slug: "a"}, {ID: gwB, Slug: "b"}}}
	d, holder, _ := newSharedCatalogDispatcher(gateways, sharedCatalogFixture(5))

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	partsA, versionA, _ := holder.SnapshotPartsFor(gwA.String())
	_, versionB, _ := holder.SnapshotPartsFor(gwB.String())

	gateways.set([]*gatewaydomain.Gateway{{ID: gwA, Slug: "a"}, {ID: gwB, Slug: "b-renamed"}})
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	gotA, gotVersionA, _ := holder.SnapshotPartsFor(gwA.String())
	if gotVersionA != versionA || &gotA[0][0] != &partsA[0][0] || &gotA[1][0] != &partsA[1][0] {
		t.Fatalf("an unchanged scope must keep its held tenant and catalog slices and its version")
	}
	if _, gotVersionB, _ := holder.SnapshotPartsFor(gwB.String()); gotVersionB == versionB {
		t.Fatalf("a changed scope must get a new version")
	}
}

func TestDispatch_CatalogChangeReversionsEveryScope(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}}}
	catalog := &mutableCatalog{catalog: sharedCatalogFixture(3)}
	d, holder, _ := newSharedCatalogDispatcher(gateways, catalog)
	codec := infrasnapshot.NewCodec()

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	before := map[string]string{}
	for _, gw := range []string{gwA.String(), gwB.String()} {
		_, before[gw], _ = holder.SnapshotPartsFor(gw)
	}

	catalog.catalog = sharedCatalogFixture(4)
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}
	for _, gw := range []string{gwA.String(), gwB.String()} {
		raw, version, _ := holder.SnapshotFor(gw)
		if version == before[gw] || version != codec.Version(raw) {
			t.Fatalf("scope %s must be reversioned over its new bytes after a catalog change", gw)
		}
	}
}

func benchmarkGateways(b *testing.B) *settableGateways {
	b.Helper()
	items := make([]*gatewaydomain.Gateway, 600)
	for i := range items {
		id, err := ids.Parse[ids.GatewayKind](fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		if err != nil {
			b.Fatal(err)
		}
		items[i] = &gatewaydomain.Gateway{ID: id, Slug: fmt.Sprintf("gw-%d", i)}
	}
	return &settableGateways{items: items}
}

func BenchmarkDispatch_ManyScopes(b *testing.B) {
	d, _, _ := newSharedCatalogDispatcher(benchmarkGateways(b), sharedCatalogFixture(3000))
	ctx := context.Background()
	if err := d.Dispatch(ctx); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := d.Dispatch(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDispatch_ManyScopesCatalogChanged(b *testing.B) {
	catalog := &mutableCatalog{catalog: sharedCatalogFixture(3000)}
	d, _, _ := newSharedCatalogDispatcher(benchmarkGateways(b), catalog)
	ctx := context.Background()
	if err := d.Dispatch(ctx); err != nil {
		b.Fatal(err)
	}
	fixtures := []fakeCatalog{sharedCatalogFixture(3001), sharedCatalogFixture(3000)}
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		catalog.catalog = fixtures[i%2]
		i++
		if err := d.Dispatch(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
