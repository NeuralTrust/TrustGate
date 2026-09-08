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

// customConsumer is a custom MCP consumer bound to two catalog-backed servers
// and one hand-configured server without a code.
func customConsumer(gw ids.GatewayID, identity consumerdomain.Identity) (*appconsumer.RoutableConsumer, *registrydomain.Registry) {
	github := githubRegistry()
	linear := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{Code: "linear"}}
	custom := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "Internal", MCPTarget: &registrydomain.MCPTarget{URL: "https://internal/mcp"}}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw,
			Type:      consumerdomain.TypeMCP,
			Identity:  identity,
		},
		Registries: []*registrydomain.Registry{github, linear, custom},
	}
	return rc, linear
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

// Access governs the Store, not a consumer. A consumer's surface is the set of
// servers an admin bound to it — the same for every caller it admits — so no
// access mode and no grant narrows it. Two places deciding one surface would
// mean an admin could bind a server the consumer's own users cannot see.
func TestScoperNeverScopesACustomConsumer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	identities := map[string]consumerdomain.Identity{
		"acts as the application": {},
		"users sign in":           {ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform},
		"the app names its users": {ActsForUsers: true, Source: consumerdomain.IdentitySourceApp},
	}
	modes := []string{
		gatewaydomain.StoreModeOpen,
		gatewaydomain.StoreModeCurated,
		gatewaydomain.StoreModeNone,
	}

	for name, identity := range identities {
		for _, mode := range modes {
			t.Run(name+"/"+mode, func(t *testing.T) {
				rc, linear := customConsumer(gw, identity)
				// A grant that names somebody else entirely, and one that names
				// this person: neither may change the answer.
				other, err := storeaccessdomain.New(gw, "github", ids.RegistryID{}, []string{"sales"}, nil)
				if err != nil {
					t.Fatalf("grant: %v", err)
				}
				mine, err := storeaccessdomain.New(gw, "linear", linear.ID, nil, []string{"ana"})
				if err != nil {
					t.Fatalf("grant: %v", err)
				}
				sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{},
					&fakeGrants{items: []*storeaccessdomain.Grant{other, mine}})

				scoped, err := sc.Scope(withModePrincipal("ana", mode, "eng"), rc)
				if err != nil {
					t.Fatalf("Scope: %v", err)
				}
				if scoped != rc {
					t.Fatalf("the consumer must be returned untouched, got a scoped copy with %d registries",
						len(scoped.Registries))
				}
			})
		}
	}
}

// The grant store is not even read for a consumer: nothing about Access is on
// that path, so an Access outage cannot affect an application's surface.
func TestScoperReadsNoGrantsForACustomConsumer(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	rc, _ := customConsumer(gw, consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform})
	grants := &fakeGrants{err: context.DeadlineExceeded}
	sc := newScoperT(t, &fakeInstalls{}, &fakeRegistries{}, grants)

	scoped, err := sc.Scope(withModePrincipal("ana", gatewaydomain.StoreModeCurated), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if scoped != rc {
		t.Fatal("the consumer must be returned untouched")
	}
}
