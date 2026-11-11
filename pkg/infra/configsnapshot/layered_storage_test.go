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
	"bytes"
	"crypto/sha256"
	"testing"
)

func assertCanonicalBucketStorage(t *testing.T, fragment *gatewayFragment) {
	t.Helper()
	starts := make(map[*byte]struct{})
	for _, b := range fragment.buckets {
		offset := 0
		for _, e := range b.elements {
			if len(e.bytes) > 0 {
				if &e.bytes[0] != &b.bytes[offset] {
					t.Fatal("an encoded element retains a byte buffer separate from its bucket")
				}
				starts[&e.bytes[0]] = struct{}{}
			}
			offset += len(e.bytes)
		}
		if offset != len(b.bytes) || (len(b.bytes) > 0 && sha256.Sum256(b.bytes) != b.digest) {
			t.Fatal("canonical bucket storage changed the encoded bytes or digest")
		}
	}
	for _, s := range gatewaySlots {
		for _, e := range fragment.slots[s] {
			if len(e.bytes) == 0 {
				continue
			}
			if _, ok := starts[&e.bytes[0]]; !ok {
				t.Fatal("a merge element retains bytes outside the canonical bucket storage")
			}
		}
	}
}

func TestLayeredSharesBucketStorageAcrossIncrementalReencoding(t *testing.T) {
	t.Parallel()
	w, gatewayID := bigGatewayWorld(300)
	f := NewFragments()
	w.rebuild(t, f)
	assertCanonicalBucketStorage(t, f.gateways[gatewayID.String()])
	before, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatal(err)
	}
	frozen := make(map[[32]byte][]byte, len(before.Layered.Fragments))
	for digest, raw := range before.Layered.Fragments {
		frozen[digest] = bytes.Clone(raw)
	}
	w.in.gateways[0].Slug = "renamed"
	if err := f.Put(w.in.gateways[0], *w.in.data[gatewayID]); err != nil {
		t.Fatal(err)
	}
	assertCanonicalBucketStorage(t, f.gateways[gatewayID.String()])
	after, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatal(err)
	}
	assertLayeredMatches(t, "incremental canonical storage", after)
	reused := 0
	for digest, raw := range before.Layered.Fragments {
		if !bytes.Equal(raw, frozen[digest]) {
			t.Fatal("updating a gateway mutated a previously published fragment")
		}
		if next, ok := after.Layered.Fragments[digest]; ok && len(raw) > 0 {
			if &raw[0] != &next[0] {
				t.Fatal("an unchanged fragment no longer reuses its published buffer")
			}
			reused++
		}
	}
	if reused == 0 {
		t.Fatal("the incremental update did not retain any unchanged fragments")
	}
	w.rebuild(t, f)
	assertCanonicalBucketStorage(t, f.gateways[gatewayID.String()])
}
