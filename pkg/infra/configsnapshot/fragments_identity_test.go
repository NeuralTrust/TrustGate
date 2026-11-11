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
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/google/uuid"
)

// world is a generated configuration: the input of a full compile plus the
// helpers that mutate it.
type world struct {
	rng *rand.Rand
	in  compileInput
}

func newID[K ids.Kind](rng *rand.Rand) ids.ID[K] {
	var u uuid.UUID
	for i := range u {
		u[i] = byte(rng.IntN(256))
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return ids.From[K](u)
}

var (
	tenants     = []string{"", "tenant-a", "tenant-b", "tenant-c", "tenant-d"}
	dataPlanes  = []string{gatewaydomain.DataPlaneHosted, gatewaydomain.DataPlaneHosted, gatewaydomain.DataPlaneHybrid, gatewaydomain.DataPlaneDedicated}
	fixedTime   = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	catalogCode = []string{"github", "slack", "jira"}
)

func newWorld(seed uint64) *world {
	w := &world{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	w.in.data = map[ids.GatewayID]*readmodel.Data{}
	w.in.caps = map[string]ratelimitdomain.TenantCaps{}
	for i := 0; i < 2+w.rng.IntN(8); i++ {
		w.addGateway()
	}
	w.mutateShared()
	w.mutateCatalog()
	return w
}

func (w *world) gateway() *gatewaydomain.Gateway {
	if len(w.in.gateways) == 0 {
		return nil
	}
	return &w.in.gateways[w.rng.IntN(len(w.in.gateways))]
}

func (w *world) addGateway() {
	g := gatewaydomain.Gateway{
		ID:           newID[ids.GatewayKind](w.rng),
		Slug:         fmt.Sprintf("gw-%d", w.rng.IntN(1_000_000)),
		Status:       "active",
		Entitlements: gatewaydomain.Entitlements{DataPlane: dataPlanes[w.rng.IntN(len(dataPlanes))]},
		CreatedAt:    fixedTime,
		UpdatedAt:    fixedTime,
	}
	if tenant := tenants[w.rng.IntN(len(tenants))]; tenant != "" {
		g.Metadata = map[string]string{gatewaydomain.MetadataTenantIDKey: tenant}
	}
	w.in.gateways = append(w.in.gateways, g)
	data := &readmodel.Data{}
	w.in.data[g.ID] = data
	for i := 0; i < w.rng.IntN(4); i++ {
		w.addRegistry(g.ID, data)
	}
	for i := 0; i < w.rng.IntN(5); i++ {
		w.addConsumer(g.ID, data)
	}
	for i := 0; i < w.rng.IntN(3); i++ {
		w.addPolicy(g.ID, data)
	}
	for i := 0; i < w.rng.IntN(4); i++ {
		w.addAuth(g.ID, data)
	}
	for i := 0; i < w.rng.IntN(3); i++ {
		w.addStoreGrant(g.ID, data)
	}
	for i := 0; i < w.rng.IntN(3); i++ {
		w.addStorePolicy(g.ID, data)
	}
	if w.rng.IntN(2) == 0 {
		data.StoreEveryone = []storeaccessdomain.Everyone{{GatewayID: g.ID, Mode: "curated", CreatedAt: fixedTime, UpdatedAt: fixedTime}}
	}
	for i := 0; i < w.rng.IntN(3); i++ {
		w.addBudget(g.ID, data)
	}
}

func (w *world) addRegistry(gw ids.GatewayID, data *readmodel.Data) {
	data.Registries = append(data.Registries, registrydomain.Registry{
		ID: newID[ids.RegistryKind](w.rng), GatewayID: gw, Name: fmt.Sprintf("reg-%d", w.rng.IntN(1000)), Enabled: w.rng.IntN(2) == 0,
	})
}

// addConsumer adds a plain consumer, or a smart-routing one whose ladder either
// references a registry of its own gateway (admitted) or one of another gateway
// (quarantined by admission).
func (w *world) addConsumer(gw ids.GatewayID, data *readmodel.Data) {
	c := consumerdomain.Consumer{
		ID: newID[ids.ConsumerKind](w.rng), GatewayID: gw, Name: fmt.Sprintf("c-%d", w.rng.IntN(1000)),
		Slug: fmt.Sprintf("c-%d", w.rng.IntN(1_000_000)), Active: w.rng.IntN(3) > 0, CreatedAt: fixedTime, UpdatedAt: fixedTime,
	}
	if w.rng.IntN(2) == 0 {
		var reg ids.RegistryID
		switch {
		case len(data.Registries) > 0 && w.rng.IntN(3) > 0:
			reg = data.Registries[w.rng.IntN(len(data.Registries))].ID
		default:
			if other := w.gateway(); other != nil && other.ID != gw && w.in.data[other.ID] != nil && len(w.in.data[other.ID].Registries) > 0 {
				reg = w.in.data[other.ID].Registries[0].ID
			} else {
				reg = newID[ids.RegistryKind](w.rng)
			}
		}
		c.RegistryIDs = []ids.RegistryID{reg}
		c.ModelPolicies = consumerdomain.ModelPolicies{reg: {Allowed: []string{"low", "mid", "high"}}}
		c.LBConfig = &consumerdomain.LBConfig{
			Enabled: true, Algorithm: algorithm.SmartRouting,
			Members: []consumerdomain.LBPoolMember{{RegistryID: reg, Model: "low"}, {RegistryID: reg, Model: "mid"}, {RegistryID: reg, Model: "high"}},
			SmartRouting: &registrydomain.SmartRoutingConfig{
				SR1: &registrydomain.SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: w.rng.IntN(2) == 0},
				Tiers: []registrydomain.SmartRoutingTier{
					{RegistryID: reg, Model: "high", MinScore: .45},
					{RegistryID: reg, Model: "low", MinScore: 0},
					{RegistryID: reg, Model: "mid", MinScore: .187},
				},
			},
		}
	}
	data.Consumers = append(data.Consumers, c)
}

func (w *world) addPolicy(gw ids.GatewayID, data *readmodel.Data) {
	data.Policies = append(data.Policies, policydomain.Policy{
		ID: newID[ids.PolicyKind](w.rng), GatewayID: gw, Name: "p", Slug: fmt.Sprintf("p-%d", w.rng.IntN(1000)),
		Enabled: true, Priority: w.rng.IntN(10),
	})
}

func (w *world) addAuth(gw ids.GatewayID, data *readmodel.Data) {
	a := authdomain.Auth{ID: newID[ids.AuthKind](w.rng), GatewayID: gw, Name: "a", Enabled: true}
	if w.rng.IntN(3) > 0 {
		a.KeyHash = fmt.Sprintf("%064x", w.rng.Uint64())
	}
	data.Auths = append(data.Auths, a)
}

func (w *world) addStoreGrant(gw ids.GatewayID, data *readmodel.Data) {
	g := storeaccessdomain.Grant{GatewayID: gw, CatalogCode: catalogCode[w.rng.IntN(len(catalogCode))], Users: []string{"u"}, CreatedAt: fixedTime, UpdatedAt: fixedTime}
	if w.rng.IntN(2) == 0 {
		g.RegistryID = newID[ids.RegistryKind](w.rng)
	}
	for _, existing := range data.StoreGrants {
		if existing.CatalogCode == g.CatalogCode && existing.RegistryID == g.RegistryID {
			return
		}
	}
	data.StoreGrants = append(data.StoreGrants, g)
}

func (w *world) addStorePolicy(gw ids.GatewayID, data *readmodel.Data) {
	p := storeaccessdomain.Policy{
		GatewayID: gw, PrincipalType: storeaccessdomain.PrincipalUser, PrincipalID: fmt.Sprintf("user-%d", w.rng.IntN(20)),
		Mode: "open", CreatedAt: fixedTime, UpdatedAt: fixedTime,
	}
	if w.rng.IntN(2) == 0 {
		p.PrincipalType = storeaccessdomain.PrincipalGroup
	}
	for _, existing := range data.StorePolicies {
		if existing.PrincipalType == p.PrincipalType && existing.PrincipalID == p.PrincipalID {
			return
		}
	}
	data.StorePolicies = append(data.StorePolicies, p)
}

func (w *world) addBudget(gw ids.GatewayID, data *readmodel.Data) {
	limit := float64(w.rng.IntN(500))
	b := keygroupdomain.Budget{GatewayID: gw, GroupID: fmt.Sprintf("group-%d", w.rng.IntN(20)), MonthlyLimitUSD: &limit, Action: "block", CreatedAt: fixedTime, UpdatedAt: fixedTime}
	for _, existing := range data.KeyGroupBudgets {
		if existing.GroupID == b.GroupID {
			return
		}
	}
	data.KeyGroupBudgets = append(data.KeyGroupBudgets, b)
}

func (w *world) mutateShared() {
	w.in.caps = map[string]ratelimitdomain.TenantCaps{}
	for _, tenant := range tenants[1:] {
		if w.rng.IntN(3) > 0 {
			w.in.caps[tenant] = ratelimitdomain.TenantCaps{TenantID: tenant, Tier: "pro", BurstPerMin: w.rng.IntN(100), QuotaPerMonth: w.rng.IntN(1000), MaxInstances: w.rng.IntN(5)}
		}
	}
	w.in.revocations = nil
	for i := 0; i < w.rng.IntN(6); i++ {
		gw := newID[ids.GatewayKind](w.rng).String()
		if g := w.gateway(); g != nil && w.rng.IntN(4) > 0 {
			gw = g.ID.String()
		}
		w.in.revocations = append(w.in.revocations, readmodel.SessionRevocation{
			GatewayID: gw, Org: fmt.Sprintf("org-%d", w.rng.IntN(3)), Subject: fmt.Sprintf("sub-%d", w.rng.IntN(5)),
			RevokedAt: fixedTime.Add(time.Duration(w.rng.IntN(1000)) * time.Second),
		})
	}
	w.in.playground = nil
	for i := 0; i < w.rng.IntN(3); i++ {
		w.in.playground = append(w.in.playground, readmodel.VerificationKey{KID: fmt.Sprintf("kid-%d", w.rng.IntN(3)), PEM: fmt.Sprintf("pem-%d", w.rng.IntN(100))})
	}
	w.in.usage = w.rng.IntN(2) == 0
}

func (w *world) mutateCatalog() {
	w.in.catalog = readmodel.Data{}
	for _, code := range []string{"openai", "anthropic", "bedrock"}[:1+w.rng.IntN(3)] {
		w.in.catalog.Providers = append(w.in.catalog.Providers, catalogdomain.Provider{ID: newID[ids.ProviderKind](w.rng), Code: code})
		for i := 0; i < 1+w.rng.IntN(4); i++ {
			w.in.catalog.CatalogModels = append(w.in.catalog.CatalogModels, readmodel.CatalogModel{
				ProviderCode: code,
				Model:        catalogdomain.Model{ID: newID[ids.ModelKind](w.rng), Slug: fmt.Sprintf("m-%d", w.rng.IntN(10))},
			})
		}
	}
}

// step applies one random change and reports which gateways it touched and
// whether it touched the catalog, the way outbox markers would name them.
func (w *world) step() (touched []ids.GatewayID, catalog bool) {
	switch w.rng.IntN(10) {
	case 0:
		w.addGateway()
		return []ids.GatewayID{w.in.gateways[len(w.in.gateways)-1].ID}, false
	case 1:
		if len(w.in.gateways) <= 1 {
			return nil, false
		}
		i := w.rng.IntN(len(w.in.gateways))
		id := w.in.gateways[i].ID
		w.in.gateways = slices.Delete(w.in.gateways, i, i+1)
		delete(w.in.data, id)
		return []ids.GatewayID{id}, false
	case 2:
		g := w.gateway()
		g.Entitlements.DataPlane = dataPlanes[w.rng.IntN(len(dataPlanes))]
		return []ids.GatewayID{g.ID}, false
	case 3:
		g := w.gateway()
		if w.in.data[g.ID] == nil {
			w.in.data[g.ID] = &readmodel.Data{}
		} else {
			w.in.data[g.ID] = nil
		}
		return []ids.GatewayID{g.ID}, false
	case 4:
		w.mutateShared()
		return nil, false
	case 5:
		w.mutateCatalog()
		return nil, true
	default:
		g := w.gateway()
		data := w.in.data[g.ID]
		if data == nil {
			return nil, false
		}
		switch w.rng.IntN(6) {
		case 0:
			w.addConsumer(g.ID, data)
		case 1:
			if len(data.Consumers) > 0 {
				i := w.rng.IntN(len(data.Consumers))
				data.Consumers = slices.Delete(data.Consumers, i, i+1)
			}
		case 2:
			w.addRegistry(g.ID, data)
		case 3:
			w.addAuth(g.ID, data)
		case 4:
			w.addStoreGrant(g.ID, data)
		default:
			g.Slug = fmt.Sprintf("renamed-%d", w.rng.IntN(1_000_000))
		}
		return []ids.GatewayID{g.ID}, false
	}
}

func (w *world) shared() appsnapshot.SharedInputs {
	return appsnapshot.SharedInputs{
		TenantCaps:         maps.Clone(w.in.caps),
		SessionRevocations: slices.Clone(w.in.revocations),
		PlaygroundKeys:     slices.Clone(w.in.playground),
		UsageEnforcement:   w.in.usage,
	}
}

func (w *world) rebuild(t *testing.T, f *Fragments) {
	t.Helper()
	if err := f.Rebuild(slices.Clone(w.in.gateways), cloneData(w.in.data), w.in.catalog); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
}

func cloneData(in map[ids.GatewayID]*readmodel.Data) map[ids.GatewayID]*readmodel.Data {
	out := make(map[ids.GatewayID]*readmodel.Data, len(in))
	for id, d := range in {
		if d == nil {
			out[id] = nil
			continue
		}
		copied := *d
		out[id] = &copied
	}
	return out
}

func (w *world) apply(t *testing.T, f *Fragments, touched []ids.GatewayID, catalog bool) {
	t.Helper()
	for _, id := range touched {
		idx := slices.IndexFunc(w.in.gateways, func(g gatewaydomain.Gateway) bool { return g.ID == id })
		if idx < 0 || w.in.data[id] == nil {
			f.Delete(id)
			continue
		}
		if err := f.Put(w.in.gateways[idx], *w.in.data[id]); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}
	if catalog {
		if err := f.PutCatalog(w.in.catalog); err != nil {
			t.Fatalf("put catalog: %v", err)
		}
	}
}

func assertIdentical(t *testing.T, label string, in compileInput, got appsnapshot.Assembled) {
	t.Helper()
	want, err := legacyCompile(in)
	if err != nil {
		t.Fatalf("%s: legacy compile: %v", label, err)
	}
	codec := NewCodec()
	if !bytes.Equal(got.Catalog, want.catalog) {
		t.Fatalf("%s: catalog part differs", label)
	}
	if !bytes.Equal(got.Global, want.global) {
		t.Fatalf("%s: global tenant part differs (%d vs %d bytes)", label, len(got.Global), len(want.global))
	}
	if codec.VersionParts(got.Global, got.Catalog) != codec.Version(append(slices.Clone(want.global), want.catalog...)) {
		t.Fatalf("%s: global version differs", label)
	}
	if len(got.Scoped) != len(want.scoped) {
		t.Fatalf("%s: %d scopes, want %d", label, len(got.Scoped), len(want.scoped))
	}
	for scope, raw := range want.scoped {
		if !bytes.Equal(got.Scoped[scope], raw) {
			t.Fatalf("%s: scope %s differs", label, scope)
		}
		if codec.VersionParts(got.Scoped[scope], got.Catalog) != codec.Version(append(slices.Clone(raw), want.catalog...)) {
			t.Fatalf("%s: scope %s version differs", label, scope)
		}
	}
}

func identitySeeds(t *testing.T, n int) []uint64 {
	t.Helper()
	base := uint64(time.Now().UnixNano())
	t.Logf("identity base seed %d", base)
	seeds := []uint64{1, 2, 3, 42, 1337}
	for i := 0; i < n; i++ {
		seeds = append(seeds, base+uint64(i))
	}
	return seeds
}

func TestFragmentsIdentityRebuild(t *testing.T) {
	t.Parallel()
	for _, seed := range identitySeeds(t, 40) {
		w := newWorld(seed)
		f := NewFragments()
		if allSkipped(w.in) {
			continue
		}
		w.rebuild(t, f)
		got, err := f.Assemble(w.shared())
		if err != nil {
			t.Fatalf("seed %d: assemble: %v", seed, err)
		}
		assertIdentical(t, fmt.Sprintf("seed %d", seed), w.in, got)
	}
}

// TestFragmentsIdentityMutationSequence applies random changes (gateways added,
// deleted, flipped between hosted and their own data plane, turned corrupt,
// entities added and removed, shared inputs and the catalog changed) and holds
// the incrementally maintained fragments to a fresh full compile after each.
func TestFragmentsIdentityMutationSequence(t *testing.T) {
	t.Parallel()
	for _, seed := range identitySeeds(t, 20) {
		w := newWorld(seed)
		if allSkipped(w.in) {
			continue
		}
		f := NewFragments()
		w.rebuild(t, f)
		for i := 0; i < 40; i++ {
			touched, catalog := w.step()
			if allSkipped(w.in) {
				break
			}
			w.apply(t, f, touched, catalog)
			got, err := f.Assemble(w.shared())
			if err != nil {
				t.Fatalf("seed %d step %d: assemble: %v", seed, i, err)
			}
			assertIdentical(t, fmt.Sprintf("seed %d step %d", seed, i), w.in, got)
		}
	}
}

func TestFragmentsUnchangedPartsKeepTheirSlices(t *testing.T) {
	t.Parallel()
	w := newWorld(7)
	f := NewFragments()
	w.rebuild(t, f)
	first, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Global) > 0 && &first.Global[0] != &second.Global[0] {
		t.Fatal("an unchanged global tenant part must be reused")
	}
	for scope, raw := range first.Scoped {
		if len(raw) > 0 && &raw[0] != &second.Scoped[scope][0] {
			t.Fatalf("an unchanged scope %s must be reused", scope)
		}
	}
	if err := f.PutCatalog(w.in.catalog); err != nil {
		t.Fatal(err)
	}
	third, err := f.Assemble(w.shared())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Catalog) > 0 && &first.Catalog[0] != &third.Catalog[0] {
		t.Fatal("an unchanged catalog must keep its slice")
	}
}

func TestFragmentsRebuildRefusesWhenEveryGatewayIsCorrupt(t *testing.T) {
	t.Parallel()
	gw := gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	err := NewFragments().Rebuild([]gatewaydomain.Gateway{gw}, map[ids.GatewayID]*readmodel.Data{gw.ID: nil}, readmodel.Data{})
	if err == nil {
		t.Fatal("rebuild must refuse an all-corrupt configuration, as a full compile does")
	}
}

func allSkipped(in compileInput) bool {
	if len(in.gateways) == 0 {
		return false
	}
	for _, g := range in.gateways {
		if in.data[g.ID] != nil {
			return false
		}
	}
	return true
}

// TestIdentityWorldsCoverEveryCase guards the generator: the identity tests
// only mean something if the worlds they draw hold admitted and quarantined
// smart routing, own-plane gateways, auths with and without a key hash, and
// usage enforcement both on and off.
func TestIdentityWorldsCoverEveryCase(t *testing.T) {
	t.Parallel()
	var admitted, quarantined, ownPlane, keyless, usageOn, usageOff int
	codec := NewCodec()
	for seed := uint64(1); seed <= 50; seed++ {
		w := newWorld(seed)
		if w.in.usage {
			usageOn++
		} else {
			usageOff++
		}
		for _, g := range w.in.gateways {
			if g.ServedByOwnDataPlane() {
				ownPlane++
			}
		}
		want, err := legacyCompile(w.in)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range want.scoped {
			snap, err := codec.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			data := snap.Data()
			for _, c := range data.Consumers {
				if c.LBConfig == nil || c.LBConfig.Algorithm != algorithm.SmartRouting {
					continue
				}
				if c.LBConfig.SmartRouting != nil {
					admitted++
				} else {
					quarantined++
				}
			}
			for _, a := range data.Auths {
				if a.KeyHash == "" {
					keyless++
				}
			}
		}
	}
	for name, n := range map[string]int{"admitted smart routing": admitted, "quarantined smart routing": quarantined, "own-plane gateways": ownPlane, "auths without key hash": keyless, "usage on": usageOn, "usage off": usageOff} {
		if n == 0 {
			t.Errorf("generated worlds never contain %s", name)
		}
	}
}
