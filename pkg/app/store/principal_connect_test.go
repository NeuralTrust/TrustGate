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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type mintedTicket struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	code         string
	instanceID   string
}

type fakeTicketMinter struct {
	got mintedTicket
	id  string
	err error
}

func (f *fakeTicketMinter) CreateServerTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code, instanceID string,
) (string, error) {
	f.got = mintedTicket{
		gatewayID:    gatewayID,
		principalSub: principalSub,
		consumerPath: consumerPath,
		code:         code,
		instanceID:   instanceID,
	}
	return f.id, f.err
}

func TestPrincipalConnectLinkerMintsAgainstTheStorePath(t *testing.T) {
	minter := &fakeTicketMinter{id: "tkt-1"}
	linker, err := appstore.NewPrincipalConnectLinker(minter)
	if err != nil {
		t.Fatalf("NewPrincipalConnectLinker: %v", err)
	}
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	link, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "com.ahrefs/mcp",
		RegistryID:   reg,
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
		instanceID:   reg.String(),
	}
	if minter.got != want {
		t.Fatalf("minted %+v, want %+v", minter.got, want)
	}
}

// Without an instance the ticket names only the code: a server the principal
// holds once needs no pinning, and the connect page opens on its own card.
func TestPrincipalConnectLinkerOmitsAnEmptyInstance(t *testing.T) {
	minter := &fakeTicketMinter{id: "tkt-2"}
	linker, _ := appstore.NewPrincipalConnectLinker(minter)
	if _, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    ids.New[ids.GatewayKind](),
		PrincipalSub: " ana ",
		Code:         " com.notion/mcp ",
	}); err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if minter.got.instanceID != "" {
		t.Fatalf("instance pinned to %q", minter.got.instanceID)
	}
	if minter.got.principalSub != "ana" || minter.got.code != "com.notion/mcp" {
		t.Fatalf("not trimmed: %+v", minter.got)
	}
}

func TestPrincipalConnectLinkerValidatesItsInput(t *testing.T) {
	linker, _ := appstore.NewPrincipalConnectLinker(&fakeTicketMinter{id: "tkt-3"})
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
	if _, err := appstore.NewPrincipalConnectLinker(nil); err == nil {
		t.Fatal("want an error without a ticket minter")
	}
}

func TestPrincipalConnectLinkerSurfacesAMintFailure(t *testing.T) {
	boom := errors.New("no connect service")
	linker, _ := appstore.NewPrincipalConnectLinker(&fakeTicketMinter{err: boom})
	if _, err := linker.LinkFor(context.Background(), appstore.PrincipalConnectRequest{
		GatewayID:    ids.New[ids.GatewayKind](),
		PrincipalSub: "ana",
		Code:         "com.notion/mcp",
	}); !errors.Is(err, boom) {
		t.Fatalf("want the mint failure, got %v", err)
	}
}
