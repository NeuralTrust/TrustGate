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
	"encoding/hex"
	"hash/fnv"
	"slices"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

// LayeredVersionPrefix starts every manifest version, so a manifest version can
// never be mistaken for a single-blob version in notices, acks or logs.
const LayeredVersionPrefix = "m1:"

// targetBucketBytes is the size a gateway bucket aims for. A gateway smaller
// than this is one bucket; a larger one is split so that a write touching a
// few entities changes a few small buckets instead of the whole gateway.
const targetBucketBytes = 64 << 10

// bucket is one fragment of a gateway: the elements whose key hashes to it, in
// slot order and, within a slot, in key order.
type bucket struct {
	elements []element
	bytes    []byte
	digest   [32]byte
}

// sharedPart is the fragment holding a flavor's shared fields (playground keys,
// tenant caps, session revocations, usage switch), cached by the stamp it was
// built from.
type sharedPart struct {
	key    []byte
	bytes  []byte
	digest [32]byte
}

func (p *sharedPart) update(s stamp, key []byte) {
	if p.key != nil && bytes.Equal(p.key, key) {
		return
	}
	var size int
	for i := range s {
		if !fromGateway[i] {
			size += len(s[i])
		}
	}
	out := make([]byte, 0, size)
	for i := range s {
		if !fromGateway[i] {
			out = append(out, s[i]...)
		}
	}
	p.key, p.bytes, p.digest = key, out, digestOf(out)
}

func digestOf(raw []byte) [32]byte {
	if len(raw) == 0 {
		return [32]byte{}
	}
	return sha256.Sum256(raw)
}

// bucketCount is the smallest power of two that brings buckets under the
// target. It depends on the gateway's size alone, so every admin replica splits
// the same configuration into the same buckets and publishes the same manifest,
// whatever its uptime; one write moves it only when the size crosses a power of
// two of the target.
func bucketCount(size int) int {
	k := 1
	for size/k > targetBucketBytes {
		k *= 2
	}
	return k
}

func bucketOf(key string, k int) int {
	if k == 1 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum64() & uint64(k-1)) // #nosec G115 -- k is a positive power of two from bucketCount, so k-1 and the masked value fit in int
}

// bucketize splits fragment into buckets keyed by element, reusing every
// bucket of previous whose elements did not change, so its bytes and digest
// are neither copied nor hashed again.
func bucketize(fragment, previous *gatewayFragment) {
	size := 0
	for _, s := range gatewaySlots {
		for _, e := range fragment.slots[s] {
			size += len(e.bytes)
		}
	}
	k := bucketCount(size)
	grouped := make([][]*element, k)
	for _, s := range gatewaySlots {
		for i := range fragment.slots[s] {
			e := &fragment.slots[s][i]
			b := bucketOf(e.key, k)
			grouped[b] = append(grouped[b], e)
		}
	}
	fragment.k = k
	fragment.buckets = make([]bucket, k)
	for b, elements := range grouped {
		if previous != nil && previous.k == k && sameElements(previous.buckets[b].elements, elements) {
			fragment.buckets[b] = previous.buckets[b]
		} else {
			fragment.buckets[b] = newBucket(elements)
		}
		for i, e := range elements {
			*e = fragment.buckets[b].elements[i]
		}
	}
}

func sameElements(a []element, b []*element) bool {
	return slices.EqualFunc(a, b, func(x element, y *element) bool {
		return x.key == y.key && bytes.Equal(x.bytes, y.bytes)
	})
}

func newBucket(elements []*element) bucket {
	size := 0
	for _, e := range elements {
		size += len(e.bytes)
	}
	out := make([]byte, 0, size)
	canonical := make([]element, len(elements))
	for i, e := range elements {
		start := len(out)
		out = append(out, e.bytes...)
		canonical[i] = element{key: e.key, bytes: out[start:len(out):len(out)]}
	}
	return bucket{elements: canonical, bytes: out, digest: digestOf(out)}
}

type manifestBuilder struct {
	fragments map[[32]byte][]byte
}

func (m *manifestBuilder) build(parts []fragmentBytes) configsyncport.Manifest {
	h := sha256.New()
	refs := make([]configsyncport.FragmentRef, 0, len(parts))
	for _, part := range parts {
		if len(part.bytes) == 0 {
			continue
		}
		m.fragments[part.digest] = part.bytes
		_, _ = h.Write(part.digest[:])
		refs = append(refs, configsyncport.FragmentRef{Digest: part.digest, Size: len(part.bytes)})
	}
	return configsyncport.Manifest{Version: LayeredVersionPrefix + hex.EncodeToString(h.Sum(nil)), Fragments: refs}
}

type fragmentBytes struct {
	bytes  []byte
	digest [32]byte
}

func (f *gatewayFragment) bucketParts(dst []fragmentBytes) []fragmentBytes {
	for _, b := range f.buckets {
		dst = append(dst, fragmentBytes{bytes: b.bytes, digest: b.digest})
	}
	return dst
}

func (f *Fragments) layered(ordered, hosted []*gatewayFragment) appsnapshot.Layered {
	m := manifestBuilder{fragments: make(map[[32]byte][]byte)}
	catalog := fragmentBytes{bytes: f.catalog, digest: f.catalogDigest}

	scoped := make(map[string]configsyncport.Manifest, len(ordered))
	for _, fragment := range ordered {
		parts := fragment.bucketParts(make([]fragmentBytes, 0, len(fragment.buckets)+2))
		parts = append(parts, fragmentBytes{bytes: fragment.shared.bytes, digest: fragment.shared.digest}, catalog)
		scoped[fragment.id] = m.build(parts)
	}

	var total int
	for _, fragment := range hosted {
		total += len(fragment.buckets)
	}
	parts := make([]fragmentBytes, 0, total+2)
	for _, fragment := range hosted {
		parts = fragment.bucketParts(parts)
	}
	parts = append(parts, fragmentBytes{bytes: f.globalShared.bytes, digest: f.globalShared.digest}, catalog)
	global := m.build(parts)

	return appsnapshot.Layered{Global: global, Scoped: scoped, Fragments: m.fragments}
}
