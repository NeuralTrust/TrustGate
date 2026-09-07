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

package store

import (
	"context"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// actsForUsersConsumer is a custom MCP consumer whose users sign in, bound to
// two catalog-backed servers and one hand-configured server without a code.
func actsForUsersConsumer(gw ids.GatewayID) (*appconsumer.RoutableConsumer, *registrydomain.Registry, *registrydomain.Registry, *registrydomain.Registry) {
	github := githubRegistry()
	linear := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{Code: "linear"}}
	custom := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "Internal", MCPTarget: &registrydomain.MCPTarget{URL: "https://internal/mcp"}}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw,
			Type:      consumerdomain.TypeMCP,
			Identity:  consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform},
		},
		Registries: []*registrydomain.Registry{github, linear, custom},
	}
	return rc, github, linear, custom
}

// withModePrincipal is a principal on a gateway whose Store default is the given
// mode, carrying the given groups.
func withModePrincipal(sub, mode string, groups ...string) context.Context {
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: sub,
		Claims:  map[string]any{identity.ClaimGroups: groups},
	})
	gw := &gatewaydomain.Gateway{}
	if mode != "" {
		gw.Metadata = map[string]string{gatewaydomain.MetadataStoreModeKey: mode}
	}
	return appgateway.WithGateway(ctx, gw)
}

func TestScoperLeavesApplicationConsumersUntouched(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	rc, _, _, _ := actsForUsersConsumer(gw)
	rc.Consumer.Identity = consumerdomain.Identity{}
	sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{}, &fakeGrants{})
	scoped, err := sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeNone), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if scoped != rc {
		t.Fatal("a consumer acting as the application is never scoped per principal")
	}
	rc.Consumer.Identity = consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourceApp}
	if scoped, _ = sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeNone), rc); scoped != rc {
		t.Fatal("app-identified end users are the application's boundary, not Access's")
	}
}

func TestScoperOpenExposesEveryConsumerRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	rc, _, _, _ := actsForUsersConsumer(gw)
	sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{}, &fakeGrants{})
	scoped, err := sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeOpen), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 3 {
		t.Fatalf("under All the consumer's whole server set stands, got %d", len(scoped.Registries))
	}
}

func TestScoperNoneEmptiesTheSurface(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	rc, _, _, _ := actsForUsersConsumer(gw)
	sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{}, &fakeGrants{})
	scoped, err := sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeNone), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 0 {
		t.Fatalf("under None nothing is exposed, got %d", len(scoped.Registries))
	}
	if len(rc.Registries) != 3 {
		t.Fatal("the shared consumer must not be mutated")
	}
}

func TestScoperCuratedKeepsOnlyGrantedRegistries(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	rc, github, linear, custom := actsForUsersConsumer(gw)
	byCode, err := storeaccessdomain.New(gw, "github", ids.RegistryID{}, []string{"eng"}, nil)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	byInstance, err := storeaccessdomain.New(gw, "linear", linear.ID, nil, []string{"ana"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{}, &fakeGrants{items: []*storeaccessdomain.Grant{byCode, byInstance}})

	scoped, err := sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeCurated, "eng"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 3 || scoped.Registries[0] != github || scoped.Registries[1] != linear || scoped.Registries[2] != custom {
		t.Fatalf("expected github (group grant by code), linear (user grant by instance) and the code-less custom server, got %+v", scoped.Registries)
	}

	// Another person, outside the group and not named, keeps only the server
	// Access cannot govern: the hand-configured one without a catalog code.
	scoped, err = sc.Scope(withModePrincipal("bob", gatewaydomain.StoreModeCurated, "sales"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 || scoped.Registries[0] != custom {
		t.Fatalf("bob has no grant on the catalog-backed servers, got %+v", scoped.Registries)
	}
}
