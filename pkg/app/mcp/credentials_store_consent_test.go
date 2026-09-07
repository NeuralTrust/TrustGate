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
