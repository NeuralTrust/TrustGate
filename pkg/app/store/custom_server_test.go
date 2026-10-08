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
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// customServer is an MCP server an admin added by URL: no catalog code, so the
// Store knows it by registrydomain.CustomStoreCode.
func customServer(name string) (*registrydomain.Registry, string) {
	reg := namedRegistry("", name)
	reg.MCPTarget.URL = "https://mcp.internal.acme/mcp"
	return reg, registrydomain.CustomStoreCode(reg.ID)
}

func TestCustomServer_GrantNamesItsRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	github := shelfRegistry("github")
	svc := newGrantServiceT(t, &fakeGrantRepo{}, &fakeRegistries{items: []*registrydomain.Registry{custom, github}}, &countingSignaler{})

	g, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: code, Users: []string{"ana"}})
	if err != nil || g.CatalogCode != code {
		t.Fatalf("a custom server of the gateway is grantable by its Store code, got %+v / %v", g, err)
	}
	if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: code, RegistryID: custom.ID, Users: []string{"ana"}}); err != nil {
		t.Fatalf("its registry is its instance: %v", err)
	}
	for name, other := range map[string]string{
		"unknown registry":            registrydomain.CustomStoreCode(ids.New[ids.RegistryKind]()),
		"a catalog server's registry": registrydomain.CustomStoreCode(github.ID),
	} {
		if _, err := svc.Set(context.Background(), SetGrantRequest{GatewayID: gw, CatalogCode: other, Users: []string{"ana"}}); !errors.Is(err, ErrCatalogEntryNotFound) {
			t.Fatalf("%s: expected ErrCatalogEntryNotFound, got %v", name, err)
		}
	}
}

func TestCustomServer_GrantedInstallsWithoutMaterialising(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	installs := &fakeInstalls{}
	ensurer := &fakeEnsurer{}
	inst := newInstallerWith(t, &fakeRegistries{items: []*registrydomain.Registry{custom}}, installs, grantsOf(codeGrant(gw, code, nil, []string{"ana"})), ensurer)

	res, err := inst.Install(context.Background(), req(gw, code))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || res.Name != "Internal tools" || res.RequiresAuth {
		t.Fatalf("a granted custom server installs under its registry name, got %+v", res)
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("a custom server is never materialised from the catalog, got %v", ensurer.ensured)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].CatalogCode != code {
		t.Fatalf("the install carries the Store code, got %+v", installs.upserts)
	}
}

func TestCustomServer_UngrantedInstallIsARequestForItsRegistry(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	installs := &fakeInstalls{}
	res, err := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{custom}}, installs).Install(context.Background(), req(gw, code))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || len(installs.upserts) != 1 || installs.upserts[0].RegistryID != custom.ID {
		t.Fatalf("a custom server nobody granted is requested, bound to its registry, got %+v / %+v", res, installs.upserts)
	}
}

func TestCustomServer_ForwardedAuthAsksTheUserToSignIn(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	custom.MCPTarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "internal"}
	inst := newInstallerWith(t, &fakeRegistries{items: []*registrydomain.Registry{custom}}, &fakeInstalls{}, grantsOf(codeGrant(gw, code, nil, []string{"ana"})), nil)
	res, err := inst.Install(context.Background(), req(gw, code))
	if err != nil || !res.RequiresAuth {
		t.Fatalf("a custom server forwarding the user's token needs their sign-in, got %+v / %v", res, err)
	}
}

func TestCustomServer_ApprovalGrantsAndListsByRegistryName(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	request := pendingInstall(t, gw, "ana", code)
	request.RegistryID = custom.ID
	installs := &fakeInstalls{findValue: request, pending: []*installationdomain.Installation{request}}
	grants := &fakeGrants{}
	ap := newApproverWith(t, installs, &fakeRegistries{items: []*registrydomain.Registry{custom}}, grants, nil)

	pending, err := ap.ListPending(context.Background(), gw)
	if err != nil || len(pending) != 1 || pending[0].Name != "Internal tools" {
		t.Fatalf("a custom request is listed under its registry name, got %+v / %v", pending, err)
	}
	if err := ap.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: code}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// A sole instance is granted at code level, which for a custom server is that registry.
	if len(grants.upserts) != 1 || grants.upserts[0].CatalogCode != code || grants.upserts[0].IsInstance() {
		t.Fatalf("approving grants the requester the custom server's code, got %+v", grants.upserts)
	}
	if request.Status != installationdomain.StatusInstalled {
		t.Fatalf("the request is installed, got %q", request.Status)
	}
}

func TestCustomServer_ApprovalOfAGoneServerIsNotShelved(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	_, code := customServer("Internal tools")
	installs := &fakeInstalls{findValue: pendingInstall(t, gw, "ana", code)}
	ap := newApproverWith(t, installs, &fakeRegistries{}, &fakeGrants{}, &fakeEnsurer{})
	if err := ap.Approve(context.Background(), ApproveRequest{GatewayID: gw, PrincipalSub: "ana", Code: code}); !errors.Is(err, ErrNotShelved) {
		t.Fatalf("a deleted custom server cannot be approved onto, got %v", err)
	}
}

func TestCustomServer_ScoperExposesTheGrantedInstall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	custom, code := customServer("Internal tools")
	other, _ := customServer("Someone else's")
	installed := mustInstall(t, gw, "ana", code)
	sc := newScoperT(t,
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{installed}},
		&fakeRegistries{items: []*registrydomain.Registry{other, custom}},
		grantsOf(codeGrant(gw, code, nil, []string{"ana"})),
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	scoped, err := sc.Scope(withPrincipal("ana"), rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 || scoped.Registries[0].ID != custom.ID {
		t.Fatalf("the install exposes exactly its custom server, got %+v", scoped.Registries)
	}
	bob, err := sc.Scope(withPrincipal("bob"), rc)
	if err != nil || len(bob.Registries) != 0 {
		t.Fatalf("nobody else sees it, got %+v / %v", bob.Registries, err)
	}
}
