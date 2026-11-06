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
	"github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

// TestFragmentsMatchLiveCompile holds the fragment encoder to the live
// CompileAll followed by the codec, as the dispatcher publishes them: every
// gateway fed to the encoder with exactly what the compiler collected for it,
// and the shared inputs the compiler read.
func TestFragmentsMatchLiveCompile(t *testing.T) {
	acme := mustGatewayID(t, capsAcme)
	globex := mustGatewayID(t, capsGlobex)
	initech := mustGatewayID(t, "33333333-3333-3333-3333-333333333333")
	globexGW := gatewayWithTeam(globex, "globex")
	globexGW.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid
	reg := mustID[ids.RegistryKind](t, "44444444-4444-4444-8444-444444444444")
	limit := 10.0
	revokedAt := time.Now().Add(-time.Minute).UTC()
	caps := []ratelimitdomain.TenantCaps{
		{TenantID: "acme", Tier: "pro", BurstPerMin: 60, QuotaPerMonth: 100, MaxInstances: 2},
		{TenantID: "globex", Tier: "free", BurstPerMin: 5},
	}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{gatewayWithTeam(acme, "acme"), globexGW, gatewayWithTeam(initech, "acme")}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			acme.String(): {
				{ID: mustConsumerID(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), GatewayID: acme, Slug: "b", RegistryIDs: []ids.RegistryID{reg}},
				{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: acme, Slug: "a"},
			},
			globex.String():  {{ID: mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"), GatewayID: globex, Slug: "c"}},
			initech.String(): {{ID: mustConsumerID(t, "dddddddd-dddd-dddd-dddd-dddddddddddd"), GatewayID: initech, Slug: "d"}},
		}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{acme.String(): {{ID: reg, GatewayID: acme, Name: "llm", Enabled: true}}}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{globex.String(): {{ID: mustID[ids.PolicyKind](t, "55555555-5555-4555-8555-555555555555"), GatewayID: globex, Name: "p"}}}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{acme.String(): {
			{ID: mustID[ids.AuthKind](t, "66666666-6666-4666-8666-666666666666"), GatewayID: acme, Name: "key", KeyHash: "hash"},
			{ID: mustID[ids.AuthKind](t, "60000000-6666-4666-8666-666666666666"), GatewayID: acme, Name: "jwt"},
		}}},
		fakeCatalog{
			providers:    []catalogdomain.Provider{{Code: "openai"}, {Code: "anthropic"}},
			modelsByCode: map[string][]catalogdomain.Model{"openai": {{Slug: "gpt"}}, "anthropic": {{Slug: "claude"}}},
		},
		nil,
		appsnapshot.WithTenantCaps(fakeTenantCaps{caps: caps}),
		appsnapshot.WithSessionRevocations(&revocationsReader{rows: []sessionrevocation.Record{
			{GatewayID: globex.String(), Org: "org", Subject: "s", RevokedAt: revokedAt},
			{GatewayID: acme.String(), Org: "org", Subject: "t", RevokedAt: revokedAt},
		}}, time.Hour),
		appsnapshot.WithKeyGroupBudgets(fakeKeyGroupBudgets{byGateway: map[string][]*keygroupdomain.Budget{
			acme.String(): {{GatewayID: acme, GroupID: "eng", MonthlyLimitUSD: &limit, Action: "block"}},
		}}),
		appsnapshot.WithStoreEveryone(fakeStoreEveryone{byGateway: map[string]*storeaccessdomain.Everyone{
			initech.String(): {GatewayID: initech, Mode: "curated"},
		}}),
		appsnapshot.WithPlaygroundTokenKeys([]readmodel.VerificationKey{{KID: "k2", PEM: "b"}, {KID: "k1", PEM: "a"}}),
		appsnapshot.WithUsageEnforcement(true),
	)

	global, scoped, catalog, err := compiler.CompileAll(context.Background())
	if err != nil {
		t.Fatalf("CompileAll: %v", err)
	}
	codec := infrasnapshot.NewCodec()
	wantCatalog, err := codec.Encode(catalog)
	if err != nil {
		t.Fatal(err)
	}
	wantGlobal, err := codec.Encode(global)
	if err != nil {
		t.Fatal(err)
	}

	fragments := infrasnapshot.NewFragments()
	shared := appsnapshot.SharedInputs{TenantCaps: map[string]ratelimitdomain.TenantCaps{}, UsageEnforcement: true,
		PlaygroundKeys: []readmodel.VerificationKey{{KID: "k2", PEM: "b"}, {KID: "k1", PEM: "a"}}}
	for _, c := range caps {
		shared.TenantCaps[c.TenantID] = c
	}
	for _, snap := range scoped {
		data := snap.Data()
		shared.SessionRevocations = append(shared.SessionRevocations, data.SessionRevocations...)
		if err := fragments.Put(data.Gateways[0], data); err != nil {
			t.Fatal(err)
		}
	}
	if err := fragments.PutCatalog(catalog.Data()); err != nil {
		t.Fatal(err)
	}
	got, err := fragments.Assemble(shared)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Catalog, wantCatalog) {
		t.Fatal("catalog part differs from the live compile")
	}
	if !bytes.Equal(got.Global, wantGlobal) {
		t.Fatal("global tenant part differs from the live compile")
	}
	if len(got.Scoped) != len(scoped) {
		t.Fatalf("%d scopes, live compile has %d", len(got.Scoped), len(scoped))
	}
	for scope, snap := range scoped {
		want, err := codec.Encode(snap)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Scoped[scope], want) {
			t.Fatalf("scope %s differs from the live compile", scope)
		}
	}
	if len(scoped[globex.String()].Data().SessionRevocations) == 0 || len(global.Data().TenantCaps) == 0 {
		t.Fatal("the fixture must exercise caps and revocations")
	}
}
