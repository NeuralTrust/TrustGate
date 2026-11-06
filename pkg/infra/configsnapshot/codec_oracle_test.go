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
	"slices"
	"testing"

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
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

func mustID[K ids.Kind](t *testing.T, s string) ids.ID[K] {
	t.Helper()
	id, err := ids.Parse[K](s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return id
}

// goldenInput is a fixed configuration covering every snapshot field: a hosted
// and a hybrid gateway of different tenants, an auth without a key hash, Store
// access, budgets, caps, revocations, playground keys, usage enforcement and a
// catalog.
func goldenInput(t *testing.T) compileInput {
	t.Helper()
	hosted := mustID[ids.GatewayKind](t, "11111111-1111-4111-8111-111111111111")
	hybrid := mustID[ids.GatewayKind](t, "22222222-2222-4222-8222-222222222222")
	empty := mustID[ids.GatewayKind](t, "00000000-0000-4000-8000-000000000001")
	reg := mustID[ids.RegistryKind](t, "33333333-3333-4333-8333-333333333333")
	gateways := []gatewaydomain.Gateway{
		{ID: hybrid, Slug: "hybrid", Status: "active", Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid},
			Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: "tenant-b"}, CreatedAt: fixedTime, UpdatedAt: fixedTime},
		{ID: hosted, Slug: "hosted", Status: "active", Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHosted},
			Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: "tenant-a"}, CreatedAt: fixedTime, UpdatedAt: fixedTime},
		{ID: empty, Slug: "empty", Status: "active", CreatedAt: fixedTime, UpdatedAt: fixedTime},
	}
	limit := 25.0
	data := map[ids.GatewayID]*readmodel.Data{
		hosted: {
			Registries: []registrydomain.Registry{{ID: reg, GatewayID: hosted, Name: "llm", Enabled: true}},
			Consumers: []consumerdomain.Consumer{
				{ID: mustID[ids.ConsumerKind](t, "44444444-4444-4444-8444-444444444444"), GatewayID: hosted, Name: "b", Slug: "b", Active: true, RegistryIDs: []ids.RegistryID{reg}, CreatedAt: fixedTime, UpdatedAt: fixedTime},
				{ID: mustID[ids.ConsumerKind](t, "40000000-4444-4444-8444-444444444444"), GatewayID: hosted, Name: "a", Slug: "a", Active: true, CreatedAt: fixedTime, UpdatedAt: fixedTime},
			},
			Policies: []policydomain.Policy{{ID: mustID[ids.PolicyKind](t, "55555555-5555-4555-8555-555555555555"), GatewayID: hosted, Name: "p", Slug: "p", Enabled: true}},
			Auths: []authdomain.Auth{
				{ID: mustID[ids.AuthKind](t, "66666666-6666-4666-8666-666666666666"), GatewayID: hosted, Name: "key", Enabled: true, KeyHash: "abc123"},
				{ID: mustID[ids.AuthKind](t, "60000000-6666-4666-8666-666666666666"), GatewayID: hosted, Name: "jwt", Enabled: true},
			},
			StoreGrants:     []storeaccessdomain.Grant{{GatewayID: hosted, CatalogCode: "github", Users: []string{"u"}, CreatedAt: fixedTime, UpdatedAt: fixedTime}},
			StorePolicies:   []storeaccessdomain.Policy{{GatewayID: hosted, PrincipalType: storeaccessdomain.PrincipalGroup, PrincipalID: "eng", Mode: "open", CreatedAt: fixedTime, UpdatedAt: fixedTime}},
			StoreEveryone:   []storeaccessdomain.Everyone{{GatewayID: hosted, Mode: "curated", CreatedAt: fixedTime, UpdatedAt: fixedTime}},
			KeyGroupBudgets: []keygroupdomain.Budget{{GatewayID: hosted, GroupID: "eng", MonthlyLimitUSD: &limit, Action: "block", CreatedAt: fixedTime, UpdatedAt: fixedTime}},
		},
		empty: {},
		hybrid: {
			Policies: []policydomain.Policy{{ID: mustID[ids.PolicyKind](t, "77777777-7777-4777-8777-777777777777"), GatewayID: hybrid, Name: "q", Slug: "q", Enabled: true}},
		},
	}
	return compileInput{
		gateways: gateways,
		data:     data,
		caps: map[string]ratelimitdomain.TenantCaps{
			"tenant-a": {TenantID: "tenant-a", Tier: "pro", BurstPerMin: 60, QuotaPerMonth: 1000, MaxInstances: 3},
			"tenant-b": {TenantID: "tenant-b", Tier: "free", BurstPerMin: 10},
		},
		revocations: []readmodel.SessionRevocation{
			{GatewayID: hybrid.String(), Org: "org", Subject: "s1", RevokedAt: fixedTime},
			{GatewayID: hosted.String(), Org: "org", Subject: "s2", RevokedAt: fixedTime},
		},
		playground: []readmodel.VerificationKey{{KID: "k2", PEM: "pem2"}, {KID: "k1", PEM: "pem1"}},
		usage:      true,
		catalog: readmodel.Data{
			Providers: []catalogdomain.Provider{{ID: mustID[ids.ProviderKind](t, "88888888-8888-4888-8888-888888888888"), Code: "openai"}},
			CatalogModels: []readmodel.CatalogModel{
				{ProviderCode: "openai", Model: catalogdomain.Model{ID: mustID[ids.ModelKind](t, "99999999-9999-4999-8999-999999999999"), Slug: "gpt"}},
			},
		},
	}
}

// The golden versions were computed from the encoder as it was before fragment
// assembly. A change here means data planes would receive different bytes for
// the same configuration.
const (
	goldenGlobalVersion = "32f32caee46d9c34de4f6f32eebfa635074b64419e6334535c988e107f54f7fd"
	goldenHostedVersion = "a6c15d4dd1bfdfa2a5b81855e9641d67c6ada548ab3a763aa8a648a11d1746d9"
	goldenHybridVersion = "f64a9a59c5f67e82aa89edb434bdc8e8c0a8a529ea37c48240fb7ba270c4e708"
)

func TestGoldenVersionsMatchTheFrozenEncoder(t *testing.T) {
	t.Parallel()
	in := goldenInput(t)
	codec := NewCodec()
	want, err := legacyCompile(in)
	if err != nil {
		t.Fatal(err)
	}
	served := func(tenant []byte) string { return codec.Version(append(slices.Clone(tenant), want.catalog...)) }
	got := map[string]string{
		"global": served(want.global),
		"hosted": served(want.scoped["11111111-1111-4111-8111-111111111111"]),
		"hybrid": served(want.scoped["22222222-2222-4222-8222-222222222222"]),
	}
	expected := map[string]string{"global": goldenGlobalVersion, "hosted": goldenHostedVersion, "hybrid": goldenHybridVersion}
	for name, version := range expected {
		if got[name] != version {
			t.Errorf("%s version = %s, want %s", name, got[name], version)
		}
	}
}

func TestGoldenFragmentsMatchTheFrozenEncoder(t *testing.T) {
	t.Parallel()
	in := goldenInput(t)
	f := NewFragments()
	if err := f.Rebuild(in.gateways, in.data, in.catalog); err != nil {
		t.Fatal(err)
	}
	got, err := f.Assemble(appsnapshot.SharedInputs{TenantCaps: in.caps, SessionRevocations: in.revocations, PlaygroundKeys: in.playground, UsageEnforcement: in.usage})
	if err != nil {
		t.Fatal(err)
	}
	assertIdentical(t, "golden", in, got)
}

// TestCodecMatchesTheFrozenEncoder keeps the live encoder byte-identical to the
// frozen one over generated configurations, for every flavor.
func TestCodecMatchesTheFrozenEncoder(t *testing.T) {
	t.Parallel()
	codec := NewCodec()
	for _, seed := range identitySeeds(t, 10) {
		w := newWorld(seed)
		for _, flavor := range flavors(w.in) {
			want, err := legacyEncode(flavor)
			if err != nil {
				t.Fatal(err)
			}
			got, err := codec.Encode(readmodel.Build(flavor))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("seed %d: live encoder differs from the frozen one", seed)
			}
		}
	}
}

func flavors(in compileInput) []readmodel.Data {
	var out []readmodel.Data
	global := readmodel.Data{PlaygroundTokenKeys: slices.Clone(in.playground), UsageEnforcement: in.usage}
	for i := range in.gateways {
		collected := in.data[in.gateways[i].ID]
		if collected == nil {
			continue
		}
		if !in.gateways[i].ServedByOwnDataPlane() {
			legacyAppendGatewayData(&global, in.gateways[i], *collected)
		}
		scoped := readmodel.Data{PlaygroundTokenKeys: slices.Clone(in.playground), UsageEnforcement: in.usage}
		legacyAppendGatewayData(&scoped, in.gateways[i], *collected)
		legacyStampTenantCaps(&scoped, in.caps)
		legacyStampSessionRevocations(&scoped, in.revocations)
		legacySortData(&scoped)
		out = append(out, scoped)
	}
	legacyStampTenantCaps(&global, in.caps)
	legacyStampSessionRevocations(&global, in.revocations)
	legacySortData(&global)
	return append(out, global)
}
