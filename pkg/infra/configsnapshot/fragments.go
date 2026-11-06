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
	"cmp"
	"container/heap"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"google.golang.org/protobuf/proto"
)

// The encoded snapshot is the concatenation of its populated fields in field
// number order (the message has no maps, so deterministic marshaling adds no
// other ordering), and a repeated message field is the concatenation of its
// elements, each encoded on its own. Caching every element's encoding and
// concatenating the elements of a flavor in the full compile's sort order
// therefore reproduces the full compile's bytes.
//
// slot is the tenant-part field order. Fields 8 and 9 (providers, catalog
// models) live only in the separately encoded catalog part, and field 1
// (version) is never set by a compile.
type slot int

const (
	slotGateways slot = iota
	slotConsumers
	slotRegistries
	slotPolicies
	slotAuths
	slotPlaygroundKeys
	slotStoreGrants
	slotStorePolicies
	slotTenantCaps
	slotSessionRevocations
	slotKeyGroupBudgets
	slotUsageEnforcement
	slotStoreEveryone
	slotCount
)

var gatewaySlots = []slot{slotGateways, slotConsumers, slotRegistries, slotPolicies, slotAuths, slotStoreGrants, slotStorePolicies, slotKeyGroupBudgets, slotStoreEveryone}

var fromGateway = func() (out [slotCount]bool) {
	for _, s := range gatewaySlots {
		out[s] = true
	}
	return out
}()

// keySeparator joins the components of a composite sort key. Database text
// cannot hold NUL, so joined keys compare like the component tuples they stand
// for.
const keySeparator = "\x00"

type element struct {
	key   string
	bytes []byte
}

type gatewayFragment struct {
	id          string
	hosted      bool
	tenant      string
	slots       [slotCount][]element
	scoped      []byte
	scopedStamp []byte
	k           int
	buckets     []bucket
	shared      sharedPart
}

// Fragments is the FragmentEncoder over the snapshot proto. It is not safe for
// concurrent use.
type Fragments struct {
	gateways      map[string]*gatewayFragment
	catalog       []byte
	catalogDigest [32]byte
	global        []byte
	globalStamp   []byte
	globalShared  sharedPart
	globalDirty   bool
}

var _ appsnapshot.FragmentEncoder = (*Fragments)(nil)

// NewFragments returns an empty fragment encoder.
func NewFragments() *Fragments {
	return &Fragments{gateways: make(map[string]*gatewayFragment), globalDirty: true}
}

// Put encodes gateway and its collected data, replacing what was held for it.
func (f *Fragments) Put(gateway gatewaydomain.Gateway, data readmodel.Data) error {
	fragment, err := encodeGateway(gateway, data)
	if err != nil {
		return err
	}
	previous, ok := f.gateways[fragment.id]
	if ok && previous.hosted {
		f.globalDirty = true
	}
	bucketize(fragment, previous)
	if ok && fragment.tenant == previous.tenant {
		fragment.shared = previous.shared
	}
	if fragment.hosted {
		f.globalDirty = true
	}
	f.gateways[fragment.id] = fragment
	return nil
}

// Delete drops a gateway.
func (f *Fragments) Delete(id ids.GatewayID) {
	key := id.String()
	if previous, ok := f.gateways[key]; ok {
		if previous.hosted {
			f.globalDirty = true
		}
		delete(f.gateways, key)
	}
}

// PutCatalog encodes the catalog. An unchanged catalog keeps the slice held so
// far, so every scope keeps sharing it.
func (f *Fragments) PutCatalog(catalog readmodel.Data) error {
	raw, err := encodeCatalog(catalog)
	if err != nil {
		return err
	}
	if f.catalog == nil || !bytes.Equal(f.catalog, raw) {
		f.catalog = raw
		f.catalogDigest = digestOf(raw)
	}
	return nil
}

// Rebuild replaces everything held. It refuses, like a full compile, when every
// gateway was skipped as corrupt.
func (f *Fragments) Rebuild(gateways []gatewaydomain.Gateway, data map[ids.GatewayID]*readmodel.Data, catalog readmodel.Data) error {
	next := make(map[string]*gatewayFragment, len(gateways))
	skipped := 0
	for i := range gateways {
		collected := data[gateways[i].ID]
		if collected == nil {
			skipped++
			continue
		}
		fragment, err := encodeGateway(gateways[i], *collected)
		if err != nil {
			return err
		}
		previous, ok := f.gateways[fragment.id]
		if ok {
			fragment.scoped, fragment.scopedStamp = reuseScoped(previous, fragment)
			if fragment.tenant == previous.tenant {
				fragment.shared = previous.shared
			}
		}
		bucketize(fragment, previous)
		next[fragment.id] = fragment
	}
	if skipped > 0 && skipped == len(gateways) {
		return fmt.Errorf("configsnapshot: every gateway (%d) skipped due to corrupt persisted config; refusing to publish empty snapshot: %w", skipped, commonerrors.ErrCorruptData)
	}
	if err := f.PutCatalog(catalog); err != nil {
		return err
	}
	f.gateways = next
	f.globalDirty = true
	return nil
}

// reuseScoped carries a previous scoped tenant part over to a rebuilt fragment
// whose elements did not change, so the slice (and the version computed over
// it) survives a full rebuild.
func reuseScoped(previous, next *gatewayFragment) ([]byte, []byte) {
	if previous.scoped == nil || previous.tenant != next.tenant {
		return nil, nil
	}
	for s := range previous.slots {
		if !slices.EqualFunc(previous.slots[s], next.slots[s], func(a, b element) bool {
			return a.key == b.key && bytes.Equal(a.bytes, b.bytes)
		}) {
			return nil, nil
		}
	}
	return previous.scoped, previous.scopedStamp
}

// Assemble builds the global tenant part from the hosted gateways and one
// tenant part per gateway, stamping each flavor with its share of shared.
func (f *Fragments) Assemble(shared appsnapshot.SharedInputs) (appsnapshot.Assembled, error) {
	revocations := sortedRevocations(shared.SessionRevocations)
	playground, err := encodePlaygroundKeys(shared.PlaygroundKeys)
	if err != nil {
		return appsnapshot.Assembled{}, err
	}
	usage, err := encodeUsage(shared.UsageEnforcement)
	if err != nil {
		return appsnapshot.Assembled{}, err
	}

	ordered := make([]*gatewayFragment, 0, len(f.gateways))
	for _, fragment := range f.gateways {
		ordered = append(ordered, fragment)
	}
	slices.SortFunc(ordered, func(a, b *gatewayFragment) int { return cmp.Compare(a.id, b.id) })

	scoped := make(map[string][]byte, len(ordered))
	hosted := make([]*gatewayFragment, 0, len(ordered))
	for _, fragment := range ordered {
		if fragment.hosted {
			hosted = append(hosted, fragment)
		}
		stamp, err := encodeStamp([]*gatewayFragment{fragment}, shared.TenantCaps, revocations, playground, usage)
		if err != nil {
			return appsnapshot.Assembled{}, err
		}
		key := stamp.key()
		if fragment.scoped == nil || !bytes.Equal(fragment.scopedStamp, key) {
			fragment.scoped = assemble([]*gatewayFragment{fragment}, stamp)
			fragment.scopedStamp = key
		}
		fragment.shared.update(stamp, key)
		scoped[fragment.id] = fragment.scoped
	}

	globalStamp, err := encodeStamp(hosted, shared.TenantCaps, revocations, playground, usage)
	if err != nil {
		return appsnapshot.Assembled{}, err
	}
	globalKey := globalStamp.key()
	if f.globalDirty || f.global == nil || !bytes.Equal(f.globalStamp, globalKey) {
		f.global = assemble(hosted, globalStamp)
		f.globalStamp = globalKey
		f.globalDirty = false
	}
	f.globalShared.update(globalStamp, globalKey)
	catalog := f.catalog
	if catalog == nil {
		catalog = []byte{}
	}
	return appsnapshot.Assembled{Global: f.global, Scoped: scoped, Catalog: catalog, Layered: f.layered(ordered, hosted)}, nil
}

type stamp [slotCount][]byte

// key identifies the stamp's content, so an unchanged stamp lets an assembled
// tenant part be reused.
func (s stamp) key() []byte {
	var n int
	for i := range s {
		n += len(s[i]) + binary.MaxVarintLen64
	}
	out := make([]byte, 0, n)
	for i := range s {
		out = binary.AppendUvarint(out, uint64(len(s[i])))
		out = append(out, s[i]...)
	}
	return out
}

func assemble(fragments []*gatewayFragment, shared stamp) []byte {
	var size int
	for _, fragment := range fragments {
		for _, s := range gatewaySlots {
			for _, e := range fragment.slots[s] {
				size += len(e.bytes)
			}
		}
	}
	for i := range shared {
		size += len(shared[i])
	}
	out := make([]byte, 0, size)
	for s := slot(0); s < slotCount; s++ {
		if fromGateway[s] {
			out = mergeSlot(out, fragments, s)
			continue
		}
		out = append(out, shared[s]...)
	}
	return out
}

// mergeSlot appends the elements of slot s from every fragment in key order.
// Each fragment's run is already sorted, so a k-way merge yields the full
// compile's order.
func mergeSlot(dst []byte, fragments []*gatewayFragment, s slot) []byte {
	runs := make(runHeap, 0, len(fragments))
	for i, fragment := range fragments {
		if len(fragment.slots[s]) > 0 {
			runs = append(runs, run{elements: fragment.slots[s], order: i})
		}
	}
	switch len(runs) {
	case 0:
		return dst
	case 1:
		for _, e := range runs[0].elements {
			dst = append(dst, e.bytes...)
		}
		return dst
	}
	heap.Init(&runs)
	for runs.Len() > 0 {
		top := &runs[0]
		dst = append(dst, top.elements[top.next].bytes...)
		top.next++
		if top.next == len(top.elements) {
			heap.Pop(&runs)
		} else {
			heap.Fix(&runs, 0)
		}
	}
	return dst
}

type run struct {
	elements []element
	next     int
	order    int
}

type runHeap []run

func (h runHeap) Len() int { return len(h) }
func (h runHeap) Less(i, j int) bool {
	a, b := h[i].elements[h[i].next].key, h[j].elements[h[j].next].key
	if a != b {
		return a < b
	}
	return h[i].order < h[j].order
}
func (h runHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *runHeap) Push(x any)   { *h = append(*h, x.(run)) }
func (h *runHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// encodeGateway encodes one gateway's elements with the same code path as a
// full compile, so admission and every JSON wrapping match. Admission only
// consults registries of the consumer's own gateway, so encoding a gateway on
// its own admits exactly what the full compile admits.
func encodeGateway(gateway gatewaydomain.Gateway, data readmodel.Data) (*gatewayFragment, error) {
	own := readmodel.Data{
		Gateways:        []gatewaydomain.Gateway{gateway},
		Consumers:       data.Consumers,
		Registries:      data.Registries,
		Policies:        data.Policies,
		Auths:           data.Auths,
		StoreGrants:     data.StoreGrants,
		StorePolicies:   data.StorePolicies,
		StoreEveryone:   data.StoreEveryone,
		KeyGroupBudgets: data.KeyGroupBudgets,
	}
	msg, err := toProto(own)
	if err != nil {
		return nil, err
	}
	fragment := &gatewayFragment{
		id:     gateway.ID.String(),
		hosted: !gateway.ServedByOwnDataPlane(),
		tenant: gateway.TenantID(),
	}
	type field struct {
		slot  slot
		count int
		key   func(int) string
		wrap  func(int) *snapshotpb.Snapshot
	}
	fields := []field{
		{slotGateways, len(msg.Gateways), func(int) string { return gateway.ID.String() },
			func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{Gateways: msg.Gateways[i : i+1]} }},
		{slotConsumers, len(msg.Consumers), func(i int) string { return own.Consumers[i].ID.String() },
			func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{Consumers: msg.Consumers[i : i+1]} }},
		{slotRegistries, len(msg.Registries), func(i int) string { return own.Registries[i].ID.String() },
			func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{Registries: msg.Registries[i : i+1]} }},
		{slotPolicies, len(msg.Policies), func(i int) string { return own.Policies[i].ID.String() },
			func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{Policies: msg.Policies[i : i+1]} }},
		{slotAuths, len(msg.Auths), func(i int) string { return own.Auths[i].ID.String() },
			func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{Auths: msg.Auths[i : i+1]} }},
		{slotStoreGrants, len(msg.StoreGrants), func(i int) string {
			g := own.StoreGrants[i]
			return compositeKey(g.GatewayID.String(), g.CatalogCode, g.RegistryID.String())
		}, func(i int) *snapshotpb.Snapshot { return &snapshotpb.Snapshot{StoreGrants: msg.StoreGrants[i : i+1]} }},
		{slotStorePolicies, len(msg.StorePolicies), func(i int) string {
			p := own.StorePolicies[i]
			return compositeKey(p.GatewayID.String(), string(p.PrincipalType), p.PrincipalID)
		}, func(i int) *snapshotpb.Snapshot {
			return &snapshotpb.Snapshot{StorePolicies: msg.StorePolicies[i : i+1]}
		}},
		{slotKeyGroupBudgets, len(msg.KeyGroupBudgets), func(i int) string {
			b := own.KeyGroupBudgets[i]
			return compositeKey(b.GatewayID.String(), b.GroupID)
		}, func(i int) *snapshotpb.Snapshot {
			return &snapshotpb.Snapshot{KeyGroupBudgets: msg.KeyGroupBudgets[i : i+1]}
		}},
		{slotStoreEveryone, len(msg.StoreEveryone), func(i int) string { return own.StoreEveryone[i].GatewayID.String() },
			func(i int) *snapshotpb.Snapshot {
				return &snapshotpb.Snapshot{StoreEveryone: msg.StoreEveryone[i : i+1]}
			}},
	}
	for _, fd := range fields {
		elements := make([]element, fd.count)
		for i := 0; i < fd.count; i++ {
			raw, err := marshalDeterministic(fd.wrap(i))
			if err != nil {
				return nil, err
			}
			elements[i] = element{key: fd.key(i), bytes: raw}
		}
		sort.SliceStable(elements, func(a, b int) bool { return elements[a].key < elements[b].key })
		fragment.slots[fd.slot] = elements
	}
	return fragment, nil
}

func compositeKey(parts ...string) string {
	return strings.Join(parts, keySeparator)
}

func encodeStamp(fragments []*gatewayFragment, caps map[string]ratelimitdomain.TenantCaps, revocations []readmodel.SessionRevocation, playground, usage []byte) (stamp, error) {
	var out stamp
	out[slotPlaygroundKeys] = playground
	out[slotUsageEnforcement] = usage

	present := make(map[string]struct{}, len(fragments))
	tenants := make([]string, 0, len(fragments))
	seen := make(map[string]struct{}, len(fragments))
	for _, fragment := range fragments {
		present[fragment.id] = struct{}{}
		if fragment.tenant == "" {
			continue
		}
		if _, dup := seen[fragment.tenant]; dup {
			continue
		}
		seen[fragment.tenant] = struct{}{}
		if _, ok := caps[fragment.tenant]; ok {
			tenants = append(tenants, fragment.tenant)
		}
	}
	slices.Sort(tenants)
	data := readmodel.Data{TenantCaps: make([]ratelimitdomain.TenantCaps, 0, len(tenants))}
	for _, tenant := range tenants {
		data.TenantCaps = append(data.TenantCaps, caps[tenant])
	}
	if len(fragments) > 0 {
		for _, row := range revocations {
			if _, ok := present[row.GatewayID]; ok {
				data.SessionRevocations = append(data.SessionRevocations, row)
			}
		}
	}
	msg, err := toProto(data)
	if err != nil {
		return stamp{}, err
	}
	if out[slotTenantCaps], err = marshalDeterministic(&snapshotpb.Snapshot{TenantCaps: msg.TenantCaps}); err != nil {
		return stamp{}, err
	}
	if out[slotSessionRevocations], err = marshalDeterministic(&snapshotpb.Snapshot{SessionRevocations: msg.SessionRevocations}); err != nil {
		return stamp{}, err
	}
	return out, nil
}

// sortedRevocations orders revocations as the full compile does, keeping the
// input order of equal keys.
func sortedRevocations(rows []readmodel.SessionRevocation) []readmodel.SessionRevocation {
	out := slices.Clone(rows)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.GatewayID != b.GatewayID {
			return a.GatewayID < b.GatewayID
		}
		if a.Org != b.Org {
			return a.Org < b.Org
		}
		return a.Subject < b.Subject
	})
	return out
}

func encodePlaygroundKeys(keys []readmodel.VerificationKey) ([]byte, error) {
	sorted := slices.Clone(keys)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].KID != sorted[j].KID {
			return sorted[i].KID < sorted[j].KID
		}
		return sorted[i].PEM < sorted[j].PEM
	})
	msg, err := toProto(readmodel.Data{PlaygroundTokenKeys: sorted})
	if err != nil {
		return nil, err
	}
	return marshalDeterministic(&snapshotpb.Snapshot{PlaygroundTokenKeys: msg.PlaygroundTokenKeys})
}

func encodeUsage(enabled bool) ([]byte, error) {
	return marshalDeterministic(&snapshotpb.Snapshot{UsageEnforcement: enabled})
}

// encodeCatalog encodes the catalog part exactly as the full compile does:
// providers by code, models by provider, slug and id.
func encodeCatalog(catalog readmodel.Data) ([]byte, error) {
	data := readmodel.Data{
		Providers:     slices.Clone(catalog.Providers),
		CatalogModels: slices.Clone(catalog.CatalogModels),
	}
	sort.SliceStable(data.Providers, func(i, j int) bool { return data.Providers[i].Code < data.Providers[j].Code })
	sort.SliceStable(data.CatalogModels, func(i, j int) bool {
		if data.CatalogModels[i].ProviderCode != data.CatalogModels[j].ProviderCode {
			return data.CatalogModels[i].ProviderCode < data.CatalogModels[j].ProviderCode
		}
		if data.CatalogModels[i].Model.Slug != data.CatalogModels[j].Model.Slug {
			return data.CatalogModels[i].Model.Slug < data.CatalogModels[j].Model.Slug
		}
		return data.CatalogModels[i].Model.ID.String() < data.CatalogModels[j].Model.ID.String()
	})
	return Codec{}.Encode(readmodel.Build(data))
}

func marshalDeterministic(msg *snapshotpb.Snapshot) ([]byte, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: marshal snapshot fragment: %w", err)
	}
	return raw, nil
}
