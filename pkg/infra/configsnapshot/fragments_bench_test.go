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

package configsnapshot

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

func BenchmarkCodecDecode(b *testing.B) {
	w := benchWorld(b)
	compiled, err := legacyCompile(w.in)
	if err != nil {
		b.Fatal(err)
	}
	raw := append(compiled.global, compiled.catalog...)
	codec := NewCodec()
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		snapshot, err := codec.Decode(raw)
		if err != nil {
			b.Fatal(err)
		}
		runtime.KeepAlive(snapshot)
	}
}

// benchWorld is a configuration of about 600 gateways with a few entities each
// and a catalog of a few thousand models.
func benchWorld(b *testing.B) *world {
	b.Helper()
	w := &world{rng: rand.New(rand.NewPCG(99, 99))}
	w.in.data = map[ids.GatewayID]*readmodel.Data{}
	for i := 0; i < 600; i++ {
		w.addGateway()
	}
	w.mutateShared()
	w.mutateCatalog()
	for i := 0; i < 3000; i++ {
		w.in.catalog.CatalogModels = append(w.in.catalog.CatalogModels, readmodel.CatalogModel{
			ProviderCode: "openai",
		})
		w.in.catalog.CatalogModels[len(w.in.catalog.CatalogModels)-1].Model.ID = newID[ids.ModelKind](w.rng)
		w.in.catalog.CatalogModels[len(w.in.catalog.CatalogModels)-1].Model.Slug = fmt.Sprintf("model-%04d", i)
		w.in.catalog.CatalogModels[len(w.in.catalog.CatalogModels)-1].Model.DisplayName = "A model with a reasonably long display name"
	}
	return w
}

func benchRebuilt(b *testing.B, w *world) *Fragments {
	b.Helper()
	f := NewFragments()
	if err := f.Rebuild(w.in.gateways, w.in.data, w.in.catalog); err != nil {
		b.Fatal(err)
	}
	if _, err := f.Assemble(w.shared()); err != nil {
		b.Fatal(err)
	}
	return f
}

// BenchmarkFragmentsOneDirtyGateway is the cost of a write: re-encode one
// hosted gateway and assemble every flavor.
func BenchmarkFragmentsOneDirtyGateway(b *testing.B) {
	w := benchWorld(b)
	f := benchRebuilt(b, w)
	var hosted int
	for i := range w.in.gateways {
		if !w.in.gateways[i].ServedByOwnDataPlane() && w.in.data[w.in.gateways[i].ID] != nil {
			hosted = i
			break
		}
	}
	g := w.in.gateways[hosted]
	data := *w.in.data[g.ID]
	shared := w.shared()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		g.Slug = fmt.Sprintf("renamed-%d", i)
		if err := f.Put(g, data); err != nil {
			b.Fatal(err)
		}
		if _, err := f.Assemble(shared); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFragmentsCatalogDirty re-encodes the catalog and assembles.
func BenchmarkFragmentsCatalogDirty(b *testing.B) {
	w := benchWorld(b)
	f := benchRebuilt(b, w)
	shared := w.shared()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		w.in.catalog.CatalogModels[0].Model.Slug = fmt.Sprintf("changed-%d", i)
		if err := f.PutCatalog(w.in.catalog); err != nil {
			b.Fatal(err)
		}
		if _, err := f.Assemble(shared); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFragmentsRebuild is a full rebuild and assembly, the cost of a
// full compile without the database.
func BenchmarkFragmentsRebuild(b *testing.B) {
	w := benchWorld(b)
	shared := w.shared()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		f := NewFragments()
		if err := f.Rebuild(w.in.gateways, w.in.data, w.in.catalog); err != nil {
			b.Fatal(err)
		}
		if _, err := f.Assemble(shared); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLegacyFullCompile is the frozen full-compile assembly and encode
// over the same configuration, for comparison.
func BenchmarkLegacyFullCompile(b *testing.B) {
	w := benchWorld(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := legacyCompile(w.in); err != nil {
			b.Fatal(err)
		}
	}
}
