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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// elementSet lists, per field, the encoding of every element a snapshot
// carries, sorted: two snapshots with equal sets carry the same entities, in
// whatever order.
func elementSet(t *testing.T, raw []byte) map[protoreflect.FieldNumber][]string {
	t.Helper()
	var msg snapshotpb.Snapshot
	if err := proto.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := map[protoreflect.FieldNumber][]string{}
	msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if !fd.IsList() {
			out[fd.Number()] = []string{v.String()}
			return true
		}
		list := v.List()
		for i := 0; i < list.Len(); i++ {
			raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(list.Get(i).Message().Interface())
			if err != nil {
				t.Fatalf("marshal element: %v", err)
			}
			out[fd.Number()] = append(out[fd.Number()], string(raw))
		}
		slices.Sort(out[fd.Number()])
		return true
	})
	return out
}

func concatManifest(t *testing.T, label string, manifest configsyncport.Manifest, fragments map[[32]byte][]byte) []byte {
	t.Helper()
	if !strings.HasPrefix(manifest.Version, LayeredVersionPrefix) {
		t.Fatalf("%s: version %q lacks the layered prefix", label, manifest.Version)
	}
	h := sha256.New()
	var out []byte
	for _, ref := range manifest.Fragments {
		raw, ok := fragments[ref.Digest]
		if !ok {
			t.Fatalf("%s: manifest references a fragment the assembly does not hold", label)
		}
		if sha256.Sum256(raw) != ref.Digest || len(raw) != ref.Size {
			t.Fatalf("%s: fragment digest or size does not match its bytes", label)
		}
		h.Write(ref.Digest[:])
		out = append(out, raw...)
	}
	if want := LayeredVersionPrefix + hex.EncodeToString(h.Sum(nil)); manifest.Version != want {
		t.Fatalf("%s: version %q, want the hash of its digests %q", label, manifest.Version, want)
	}
	return out
}

func assertLayeredMatches(t *testing.T, label string, got appsnapshot.Assembled) {
	t.Helper()
	codec := NewCodec()
	check := func(flavor string, tenant []byte, manifest configsyncport.Manifest) {
		v1 := append(slices.Clone(tenant), got.Catalog...)
		layered := concatManifest(t, label+" "+flavor, manifest, got.Layered.Fragments)
		want, have := elementSet(t, v1), elementSet(t, layered)
		if len(want) != len(have) {
			t.Fatalf("%s %s: layered snapshot has %d fields, single blob %d", label, flavor, len(have), len(want))
		}
		for field, elements := range want {
			if !slices.Equal(elements, have[field]) {
				t.Fatalf("%s %s: field %d differs between layered and single blob", label, flavor, field)
			}
		}
		if _, err := codec.Decode(layered); err != nil {
			t.Fatalf("%s %s: decode layered: %v", label, flavor, err)
		}
	}
	check("global", got.Global, got.Layered.Global)
	if len(got.Layered.Scoped) != len(got.Scoped) {
		t.Fatalf("%s: %d layered scopes, want %d", label, len(got.Layered.Scoped), len(got.Scoped))
	}
	for scope, tenant := range got.Scoped {
		check("scope "+scope, tenant, got.Layered.Scoped[scope])
	}
}

func TestLayeredDecodesToTheSameSnapshotAsTheSingleBlob(t *testing.T) {
	t.Parallel()
	for _, seed := range identitySeeds(t, 10) {
		w := newWorld(seed)
		if allSkipped(w.in) {
			continue
		}
		f := NewFragments()
		w.rebuild(t, f)
		for i := 0; i < 30; i++ {
			got, err := f.Assemble(w.shared())
			if err != nil {
				t.Fatalf("seed %d step %d: assemble: %v", seed, i, err)
			}
			assertLayeredMatches(t, fmt.Sprintf("seed %d step %d", seed, i), got)
			touched, catalog := w.step()
			if allSkipped(w.in) {
				break
			}
			w.apply(t, f, touched, catalog)
		}
	}
}

// bigGatewayWorld is one hosted gateway holding n consumers and n keys, the
// shape of a tenant whose automation creates one consumer and key per agent.
func bigGatewayWorld(n int) (*world, ids.GatewayID) {
	w := &world{rng: rand.New(rand.NewPCG(5, 5))}
	w.in.data = map[ids.GatewayID]*readmodel.Data{}
	gw := gatewaydomain.Gateway{
		ID: newID[ids.GatewayKind](w.rng), Slug: "big", Status: "active",
		Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHosted},
		CreatedAt:    fixedTime, UpdatedAt: fixedTime,
	}
	w.in.gateways = append(w.in.gateways, gw)
	data := &readmodel.Data{}
	w.in.data[gw.ID] = data
	w.addRegistry(gw.ID, data)
	for i := 0; i < n; i++ {
		w.addConsumer(gw.ID, data)
		w.addAuth(gw.ID, data)
	}
	w.mutateCatalog()
	return w, gw.ID
}

func digestSet(m configsyncport.Manifest) (map[[32]byte]int, int) {
	out := make(map[[32]byte]int, len(m.Fragments))
	total := 0
	for _, ref := range m.Fragments {
		out[ref.Digest] = ref.Size
		total += ref.Size
	}
	return out, total
}

func TestLayeredAddingOneConsumerChangesAFewBuckets(t *testing.T) {
	t.Parallel()
	w, gw := bigGatewayWorld(5000)
	f := NewFragments()
	w.rebuild(t, f)
	before, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	beforeSet, beforeBytes := digestSet(before.Layered.Scoped[gw.String()])

	data := w.in.data[gw]
	w.addConsumer(gw, data)
	w.addAuth(gw, data)
	if err := f.Put(w.in.gateways[0], *data); err != nil {
		t.Fatalf("put: %v", err)
	}
	after, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	assertLayeredMatches(t, "after write", after)

	manifest := after.Layered.Scoped[gw.String()]
	changed, changedBytes := 0, 0
	for _, ref := range manifest.Fragments {
		if _, ok := beforeSet[ref.Digest]; !ok {
			changed++
			changedBytes += ref.Size
		}
	}
	t.Logf("gateway with 5000 consumers and keys: %d fragments, %d bytes; one write changed %d fragments, %d bytes",
		len(manifest.Fragments), beforeBytes, changed, changedBytes)
	if len(manifest.Fragments) < 16 {
		t.Fatalf("a gateway of %d bytes is split into only %d fragments", beforeBytes, len(manifest.Fragments))
	}
	if changed > 4 {
		t.Fatalf("one consumer and one key changed %d fragments, want at most 4", changed)
	}
	if changedBytes*20 > beforeBytes {
		t.Fatalf("one write changed %d of %d bytes", changedBytes, beforeBytes)
	}
	globalBefore, _ := digestSet(before.Layered.Global)
	globalChanged := 0
	for _, ref := range after.Layered.Global.Fragments {
		if _, ok := globalBefore[ref.Digest]; !ok {
			globalChanged++
		}
	}
	if globalChanged > 4 {
		t.Fatalf("one write changed %d global fragments, want at most 4", globalChanged)
	}
}

func TestLayeredUnchangedGatewaysKeepTheirFragments(t *testing.T) {
	t.Parallel()
	w := newWorld(11)
	for i := 0; i < 5; i++ {
		w.addGateway()
	}
	f := NewFragments()
	w.rebuild(t, f)
	before, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	w.rebuild(t, f)
	after, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if before.Layered.Global.Version != after.Layered.Global.Version {
		t.Fatalf("a rebuild of unchanged data changed the global manifest")
	}
	for scope, m := range before.Layered.Scoped {
		if after.Layered.Scoped[scope].Version != m.Version {
			t.Fatalf("a rebuild of unchanged data changed the manifest of scope %s", scope)
		}
	}
}

func TestBucketCountDependsOnlyOnSize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		size, want int
	}{
		{size: 0, want: 1},
		{size: targetBucketBytes, want: 1},
		{size: targetBucketBytes + 1, want: 2},
		{size: 2 * targetBucketBytes, want: 2},
		{size: 2*targetBucketBytes + 2, want: 4},
		{size: 10 * targetBucketBytes, want: 16},
	}
	for _, c := range cases {
		if got := bucketCount(c.size); got != c.want {
			t.Fatalf("bucketCount(%d) = %d, want %d", c.size, got, c.want)
		}
	}
}

func TestLayeredReplicasWithDifferentHistoriesPublishTheSameManifests(t *testing.T) {
	t.Parallel()
	w, gw := bigGatewayWorld(60)
	longRunning := NewFragments()
	w.rebuild(t, longRunning)
	for i := 0; i < 60; i++ {
		data := w.in.data[gw]
		w.addConsumer(gw, data)
		if err := longRunning.Put(w.in.gateways[0], *data); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	restarted := NewFragments()
	w.rebuild(t, restarted)

	a, err := longRunning.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	b, err := restarted.Assemble(w.shared())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if a.Layered.Global.Version != b.Layered.Global.Version {
		t.Fatal("a long-running encoder and a freshly rebuilt one publish different global manifests for the same configuration")
	}
	for scope, m := range a.Layered.Scoped {
		if b.Layered.Scoped[scope].Version != m.Version {
			t.Fatalf("scope %s: manifests differ between replicas with different histories", scope)
		}
	}
}
