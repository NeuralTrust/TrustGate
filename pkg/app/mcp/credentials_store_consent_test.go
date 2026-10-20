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

package mcp

import (
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// The Store connect page attaches registries only for a ticket that names the
// server, so a consent link minted from a Store tools/call must carry the
// catalog code; a plain consumer ticket would land the user on an empty page.
func TestCredentialResolver_StoreConsentTicketNamesTheServer(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: "linear", ClientID: "id",
		AuthorizeURL: "https://linear/a", TokenURL: "https://linear/t",
	}
	reg, err := registrydomain.NewMCPRegistry(gw, "Linear", "", &registrydomain.MCPTarget{
		Code: "app.linear/mcp", URL: "https://mcp.linear.app/mcp", Auth: cfg,
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	ctx := principalCtx(&identity.Principal{Subject: "alice"})

	connect := &stubConnect{ticket: "srv-ticket"}
	r := NewCredentialResolver(nil, &memVault{}, connect, infraoauth.NewProviderClient(nil), discardLogger())
	target := Target{}
	err = r.Apply(ctx, store, reg, &target)
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError", err)
	}
	if consent.Ticket != "srv-ticket" || consent.Path != appconsumer.MCPPath(consumerdomain.StoreSlug) {
		t.Fatalf("consent = %+v", consent)
	}
	if len(connect.serverTicketCodes) != 1 || connect.serverTicketCodes[0] != "app.linear/mcp" {
		t.Fatalf("Store consent must mint a server ticket for the registry's code, got %v", connect.serverTicketCodes)
	}

	// A regular consumer keeps the consumer-wide ticket.
	plain := &stubConnect{ticket: "plain"}
	r = NewCredentialResolver(nil, &memVault{}, plain, infraoauth.NewProviderClient(nil), discardLogger())
	if err := r.Apply(ctx, mcpConsumer(gw), reg, &Target{}); !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError", err)
	}
	if len(plain.serverTicketCodes) != 0 {
		t.Fatalf("a non-Store consumer must not mint a server ticket, got %v", plain.serverTicketCodes)
	}
}

// Two installs of one catalog code are two servers. A tools/call that needs
// connect on instance B must mint a ticket pinned to B: the connect link is
// that ticket, and an empty instance id makes the page focus whichever row of
// the code comes first.
func TestCredentialResolver_StoreConsentTicketPinsTheCalledInstance(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	instance := func(name, upstream string) *registrydomain.Registry {
		reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
			Code: "io.n8n/mcp",
			URL:  upstream,
			Auth: &registrydomain.MCPAuth{
				Mode: registrydomain.MCPAuthModeForwarded, Provider: "io.n8n/mcp", ClientID: "id",
				AuthorizeURL: "https://n8n.example/a", TokenURL: "https://n8n.example/t",
			},
		})
		if err != nil {
			t.Fatalf("registry %s: %v", name, err)
		}
		return reg
	}
	instanceA := instance("n8n A", "https://a.n8n.example/mcp")
	instanceB := instance("n8n B", "https://b.n8n.example/mcp")
	if instanceA.ID == instanceB.ID {
		t.Fatal("the two instances must have distinct ids")
	}

	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	ctx := principalCtx(&identity.Principal{Subject: "alice"})
	connect := &stubConnect{ticket: "srv-ticket-b"}
	r := NewCredentialResolver(nil, &memVault{}, connect, infraoauth.NewProviderClient(nil), discardLogger())

	err := r.Apply(ctx, store, instanceB, &Target{})
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError", err)
	}
	link := consent.Path + "/connect?ticket=" + consent.Ticket
	if consent.Ticket != "srv-ticket-b" || link != appconsumer.MCPPath(consumerdomain.StoreSlug)+"/connect?ticket=srv-ticket-b" {
		t.Fatalf("needs-connect link = %q, consent = %+v", link, consent)
	}
	if len(connect.serverTicketCodes) != 1 || connect.serverTicketCodes[0] != "io.n8n/mcp" {
		t.Fatalf("ticket code = %v, want io.n8n/mcp", connect.serverTicketCodes)
	}
	if len(connect.serverTicketInstances) != 1 || connect.serverTicketInstances[0] != instanceB.ID.String() {
		t.Fatalf("needs-connect ticket instance = %v, want instance B %s (instance A is %s)",
			connect.serverTicketInstances, instanceB.ID, instanceA.ID)
	}
}

// A user with two installs of one code is handed a clone whose id is the
// installation row and whose InstanceOf is the persisted shelf. The connect
// page looks the pin up by registry id, so the ticket has to name shelf B.
func TestCredentialResolver_StoreConsentTicketPinsTheShelfBehindTheClone(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	instance := func(name, upstream string) *registrydomain.Registry {
		reg, err := registrydomain.NewMCPRegistry(gw, name, "", &registrydomain.MCPTarget{
			Code: "io.n8n/mcp",
			URL:  upstream,
			Auth: &registrydomain.MCPAuth{
				Mode: registrydomain.MCPAuthModeForwarded, Provider: "io.n8n/mcp", ClientID: "id",
				AuthorizeURL: "https://n8n.example/a", TokenURL: "https://n8n.example/t",
			},
		})
		if err != nil {
			t.Fatalf("registry %s: %v", name, err)
		}
		return reg
	}
	instanceA := instance("n8n A", "https://a.n8n.example/mcp")
	instanceB := instance("n8n B", "https://b.n8n.example/mcp")
	installRow := ids.New[ids.RegistryKind]()
	clone := *instanceB
	target := *instanceB.MCPTarget
	clone.MCPTarget = &target
	clone.ID = installRow
	clone.InstanceOf = instanceB.ID
	if clone.ScopeKey() != instanceB.ID || clone.ID == instanceB.ID {
		t.Fatalf("clone scope = %s id = %s, want shelf %s", clone.ScopeKey(), clone.ID, instanceB.ID)
	}

	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	connect := &stubConnect{ticket: "srv-ticket-b"}
	r := NewCredentialResolver(nil, &memVault{}, connect, infraoauth.NewProviderClient(nil), discardLogger())
	err := r.Apply(principalCtx(&identity.Principal{Subject: "alice"}), store, &clone, &Target{})
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError", err)
	}
	if consent.Path+"/connect?ticket="+consent.Ticket != appconsumer.MCPPath(consumerdomain.StoreSlug)+"/connect?ticket=srv-ticket-b" {
		t.Fatalf("needs-connect link ticket = %q path = %q", consent.Ticket, consent.Path)
	}
	if len(connect.serverTicketInstances) != 1 || connect.serverTicketInstances[0] != instanceB.ID.String() {
		t.Fatalf("needs-connect ticket instance = %v, want shelf B %s (install row %s, instance A %s)",
			connect.serverTicketInstances, instanceB.ID, installRow, instanceA.ID)
	}
}

// A pending stand-in uses the installation id and is not in the registry
// list yet. Pinning that id would make the connect page find nothing.
func TestCredentialResolver_StoreConsentTicketLeavesAPendingShelfUnpinned(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "n8n", "", &registrydomain.MCPTarget{
		Code: "io.n8n/mcp",
		URL:  "https://n8n.example/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "io.n8n/mcp", ClientID: "id",
			AuthorizeURL: "https://n8n.example/a", TokenURL: "https://n8n.example/t",
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	reg.ID = ids.New[ids.RegistryKind]()
	reg.InstanceOf = reg.ID
	reg.MCPTarget.Origin = registrydomain.MCPOriginPending

	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	connect := &stubConnect{ticket: "srv-ticket-pending"}
	r := NewCredentialResolver(nil, &memVault{}, connect, infraoauth.NewProviderClient(nil), discardLogger())
	err = r.Apply(principalCtx(&identity.Principal{Subject: "alice"}), store, reg, &Target{})
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError", err)
	}
	if consent.Ticket != "srv-ticket-pending" {
		t.Fatalf("ticket = %q", consent.Ticket)
	}
	if len(connect.serverTicketInstances) != 1 || connect.serverTicketInstances[0] != "" {
		t.Fatalf("pending shelf ticket instance = %v, want unpinned", connect.serverTicketInstances)
	}
}
