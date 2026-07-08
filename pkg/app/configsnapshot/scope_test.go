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
	"context"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

func gatewayWithTeam(id ids.GatewayID, team string) *gatewaydomain.Gateway {
	return &gatewaydomain.Gateway{ID: id, Metadata: map[string]string{gatewaydomain.MetadataTeamIDKey: team}}
}

func twoTenantCompiler(t *testing.T, acme, globex ids.GatewayID, acmeConsumer, globexConsumer ids.ConsumerID) *appsnapshot.Compiler {
	t.Helper()
	return appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{
			gatewayWithTeam(acme, "acme"),
			gatewayWithTeam(globex, "globex"),
		}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			acme.String():   {{ID: acmeConsumer, GatewayID: acme}},
			globex.String(): {{ID: globexConsumer, GatewayID: globex}},
		}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
		fakeCatalog{providers: []catalogdomain.Provider{{Code: "openai"}}},
		nil,
	)
}

func TestCompilerCompileForIsolatesScope(t *testing.T) {
	acme := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	globex := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	acmeConsumer := mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	globexConsumer := mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")

	compiler := twoTenantCompiler(t, acme, globex, acmeConsumer, globexConsumer)

	snap, err := compiler.CompileFor(context.Background(), "acme")
	if err != nil {
		t.Fatalf("compile for acme: %v", err)
	}
	data := snap.Data()
	if len(data.Gateways) != 1 || data.Gateways[0].ID != acme {
		t.Fatalf("expected only the acme gateway, got %+v", data.Gateways)
	}
	if len(data.Consumers) != 1 || data.Consumers[0].ID != acmeConsumer {
		t.Fatalf("expected only the acme consumer, got %+v", data.Consumers)
	}
	if len(data.Providers) != 1 {
		t.Fatalf("expected shared catalog in scope snapshot, got %d providers", len(data.Providers))
	}
}

func TestCompilerCompileAllPartitionsAndIsolates(t *testing.T) {
	acme := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	globex := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	acmeConsumer := mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	globexConsumer := mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")

	compiler := twoTenantCompiler(t, acme, globex, acmeConsumer, globexConsumer)

	global, scoped, err := compiler.CompileAll(context.Background())
	if err != nil {
		t.Fatalf("compile all: %v", err)
	}
	if len(global.Data().Gateways) != 2 {
		t.Fatalf("expected both gateways in the whole snapshot, got %d", len(global.Data().Gateways))
	}
	if len(scoped) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(scoped))
	}
	acmeSnap, ok := scoped["acme"]
	if !ok {
		t.Fatal("missing acme scope")
	}
	if gws := acmeSnap.Data().Gateways; len(gws) != 1 || gws[0].ID != acme {
		t.Fatalf("acme scope leaked other gateways: %+v", gws)
	}
	for _, cs := range acmeSnap.Data().Consumers {
		if cs.ID == globexConsumer {
			t.Fatal("globex consumer leaked into acme scope")
		}
	}
	if len(acmeSnap.Data().Providers) != 1 {
		t.Fatalf("expected shared catalog in acme scope, got %d", len(acmeSnap.Data().Providers))
	}
	globexSnap := scoped["globex"]
	if gws := globexSnap.Data().Gateways; len(gws) != 1 || gws[0].ID != globex {
		t.Fatalf("globex scope leaked other gateways: %+v", gws)
	}
}

func TestHolderPartitionedFailsClosed(t *testing.T) {
	h := appsnapshot.NewHolder()
	h.SetPartitioned([]byte("global"), "vg", map[string]appsnapshot.ScopedSnapshot{
		"acme": {Raw: []byte("acme-cfg"), Version: "va"},
	})

	if raw, version, ok := h.SnapshotFor(""); !ok || string(raw) != "global" || version != "vg" {
		t.Fatalf("empty scope = (%q,%q,%v), want the whole snapshot", raw, version, ok)
	}
	if raw, version, ok := h.SnapshotFor("acme"); !ok || string(raw) != "acme-cfg" || version != "va" {
		t.Fatalf("acme scope = (%q,%q,%v), want the acme snapshot", raw, version, ok)
	}
	if _, _, ok := h.SnapshotFor("globex"); ok {
		t.Fatal("unknown scope must fail closed, not fall back to the whole snapshot")
	}
}
