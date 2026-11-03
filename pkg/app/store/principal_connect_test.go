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

package store_test

import (
	"context"
	"errors"
	"testing"

	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type mintedTicket struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	code         string
	instanceID   string
	resumeURL    string
}

type fakeTicketMinter struct {
	got mintedTicket
	id  string
	err error
}

type connectRegistries struct {
	items []*registrydomain.Registry
}

func (r connectRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return r.items, len(r.items), nil
}

type connectGrants struct {
	items []*storeaccessdomain.Grant
}

func (g connectGrants) ListByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	return g.items, nil
}

type connectGateways struct {
	gateway *gatewaydomain.Gateway
}

func (g connectGateways) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return g.gateway, nil
}

func connectGateway(gatewayID ids.GatewayID, mode string) connectGateways {
	return connectGateways{gateway: &gatewaydomain.Gateway{
		ID: gatewayID, Metadata: gatewaydomain.WithStoreMode(nil, mode),
	}}
}

func (f *fakeTicketMinter) CreateResumableServerTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code, instanceID, resumeURL string,
) (string, error) {
	f.got = mintedTicket{
		gatewayID:    gatewayID,
		principalSub: principalSub,
		consumerPath: consumerPath,
		code:         code,
		instanceID:   instanceID,
		resumeURL:    resumeURL,
	}
	return f.id, f.err
}

func TestPrincipalConnectLinkerMintsAgainstTheStorePath(t *testing.T) {
	minter := &fakeTicketMinter{id: "tkt-1"}
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.ahrefs/mcp"},
	}
	linker, err := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		connectGrants{},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeOpen),
	)
	if err != nil {
		t.Fatalf("NewPrincipalConnectLinker: %v", err)
	}
	link, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "com.ahrefs/mcp",
		RegistryID:   registry.ID,
	})
	if err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if link.Ticket != "tkt-1" || link.ConsumerPath != "/store/mcp" {
		t.Fatalf("link: %+v", link)
	}
	want := mintedTicket{
		gatewayID:    gw,
		principalSub: "ana",
		consumerPath: "/store/mcp",
		code:         "com.ahrefs/mcp",
		instanceID:   registry.ID.String(),
	}
	if minter.got != want {
		t.Fatalf("minted %+v, want %+v", minter.got, want)
	}
}

func TestPrincipalConnectLinkerPinsAnEmptyInstance(t *testing.T) {
	minter := &fakeTicketMinter{id: "tkt-2"}
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	linker, _ := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		nil,
		nil,
		connectGateway(gw, gatewaydomain.StoreModeOpen),
	)
	if _, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    gw,
		PrincipalSub: " ana ",
		Code:         " com.notion/mcp ",
	}); err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if minter.got.instanceID != registry.ID.String() {
		t.Fatalf("instance pinned to %q, want %q", minter.got.instanceID, registry.ID)
	}
	if minter.got.principalSub != "ana" || minter.got.code != "com.notion/mcp" {
		t.Fatalf("not trimmed: %+v", minter.got)
	}
}

// The Portal names the screen the link was opened from, and the ticket carries
// it so the connect page can send the user back there.
func TestPrincipalConnectLinkerCarriesTheResumeURL(t *testing.T) {
	minter := &fakeTicketMinter{id: "tkt-4"}
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	linker, _ := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		nil,
		nil,
		connectGateway(gw, gatewaydomain.StoreModeOpen),
	)
	if _, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "com.notion/mcp",
		ResumeURL:    " https://app.neuraltrust.ai/v2/t/portal ",
	}); err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if minter.got.resumeURL != "https://app.neuraltrust.ai/v2/t/portal" {
		t.Fatalf("resume url = %q", minter.got.resumeURL)
	}
}

func TestPrincipalConnectLinkerValidatesItsInput(t *testing.T) {
	linker, _ := appstore.NewPrincipalConnectLinker(&fakeTicketMinter{id: "tkt-3"}, connectRegistries{}, nil, nil, nil)
	cases := map[string]appstore.PrincipalConnectRequest{
		"no gateway":   {PrincipalSub: "ana", Code: "com.notion/mcp"},
		"no principal": {GatewayID: ids.New[ids.GatewayKind](), Code: "com.notion/mcp"},
		"no code":      {GatewayID: ids.New[ids.GatewayKind](), PrincipalSub: "ana"},
	}
	for name, in := range cases {
		if _, err := linker.LinkFor(context.Background(), in); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: want a validation error, got %v", name, err)
		}
	}
}

func TestPrincipalConnectLinkerNeedsAMinter(t *testing.T) {
	if _, err := appstore.NewPrincipalConnectLinker(nil, connectRegistries{}, nil, nil, nil); err == nil {
		t.Fatal("want an error without a ticket minter")
	}
	if _, err := appstore.NewPrincipalConnectLinker(&fakeTicketMinter{}, nil, nil, nil, nil); err == nil {
		t.Fatal("want an error without a registry lister")
	}
}

func TestPrincipalConnectLinkerSurfacesAMintFailure(t *testing.T) {
	boom := errors.New("no connect service")
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	linker, _ := appstore.NewPrincipalConnectLinker(
		&fakeTicketMinter{err: boom},
		connectRegistries{items: []*registrydomain.Registry{registry}},
		nil,
		nil,
		connectGateway(gw, gatewaydomain.StoreModeOpen),
	)
	if _, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "com.notion/mcp",
	}); !errors.Is(err, boom) {
		t.Fatalf("want the mint failure, got %v", err)
	}
}

func TestPrincipalConnectLinkerRejectsAnUnpinnedUngrantedInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	minter := &fakeTicketMinter{}
	linker, _ := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		connectGrants{},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeCurated),
	)
	_, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: "com.notion/mcp",
	})
	if !errors.Is(err, commonerrors.ErrForbidden) {
		t.Fatalf("LinkFor error = %v, want forbidden", err)
	}
	if minter.got.instanceID != "" {
		t.Fatalf("minted an ungranted instance: %+v", minter.got)
	}
}

func TestPrincipalConnectLinkerRejectsAnUngrantedInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	minter := &fakeTicketMinter{id: "must-not-mint"}
	linker, _ := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		connectGrants{},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeCurated),
	)
	_, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: "com.notion/mcp", RegistryID: registry.ID,
	})
	if !errors.Is(err, commonerrors.ErrForbidden) {
		t.Fatalf("LinkFor error = %v, want forbidden", err)
	}
	if minter.got.instanceID != "" {
		t.Fatalf("minted an ungranted instance: %+v", minter.got)
	}
}

func TestPrincipalConnectLinkerRejectsWhenStoreModeIsNone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	linker, _ := appstore.NewPrincipalConnectLinker(
		&fakeTicketMinter{},
		connectRegistries{items: []*registrydomain.Registry{registry}},
		connectGrants{},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeNone),
	)
	_, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: "com.notion/mcp", RegistryID: registry.ID,
	})
	if !errors.Is(err, appstore.ErrStoreClosed) {
		t.Fatalf("LinkFor error = %v, want ErrStoreClosed", err)
	}
}

func TestPrincipalConnectLinkerMintsForAGrantedInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.notion/mcp"},
	}
	grant, err := storeaccessdomain.New(gw, "com.notion/mcp", registry.ID, nil, []string{"ana"})
	if err != nil {
		t.Fatalf("new grant: %v", err)
	}
	minter := &fakeTicketMinter{id: "tkt-granted"}
	linker, _ := appstore.NewPrincipalConnectLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		connectGrants{items: []*storeaccessdomain.Grant{grant}},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeCurated),
	)
	link, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: "com.notion/mcp", RegistryID: registry.ID,
	})
	if err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if link.Ticket != "tkt-granted" || minter.got.instanceID != registry.ID.String() {
		t.Fatalf("granted instance was not minted: link=%+v ticket=%+v", link, minter.got)
	}
}
