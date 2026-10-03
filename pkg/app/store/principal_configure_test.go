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

type mintedConfigure struct {
	gatewayID    ids.GatewayID
	principalSub string
	consumerPath string
	code         string
	instanceID   string
	groups       []string
}

type fakeConfigureMinter struct {
	got mintedConfigure
	id  string
	err error
}

func (f *fakeConfigureMinter) CreateConfigureTicket(
	_ context.Context,
	gatewayID ids.GatewayID,
	principalSub, consumerPath, code, instanceID string,
	groups []string,
) (string, error) {
	f.got = mintedConfigure{gatewayID, principalSub, consumerPath, code, instanceID, groups}
	return f.id, f.err
}

func TestPrincipalConfigureLinkerMintsAgainstTheStorePath(t *testing.T) {
	minter := &fakeConfigureMinter{id: "cfg-1"}
	linker, err := appstore.NewPrincipalConfigureLinker(minter)
	if err != nil {
		t.Fatalf("NewPrincipalConfigureLinker: %v", err)
	}
	gw := ids.New[ids.GatewayKind]()
	link, err := linker.LinkFor(context.Background(), appstore.PrincipalConfigureRequest{
		GatewayID:    gw,
		PrincipalSub: " ana ",
		Code:         " com.snowflake/mcp ",
		InstanceID:   " inst-1 ",
		Groups:       []string{"eng"},
	})
	if err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if link.Ticket != "cfg-1" || link.ConsumerPath != "/store/mcp" {
		t.Fatalf("link: %+v", link)
	}
	if minter.got.principalSub != "ana" || minter.got.code != "com.snowflake/mcp" ||
		minter.got.instanceID != "inst-1" || minter.got.consumerPath != "/store/mcp" ||
		minter.got.gatewayID != gw || len(minter.got.groups) != 1 {
		t.Fatalf("minted %+v", minter.got)
	}
}

func TestPrincipalConfigureLinkerValidatesItsInput(t *testing.T) {
	linker, _ := appstore.NewPrincipalConfigureLinker(&fakeConfigureMinter{id: "cfg-2"})
	cases := map[string]appstore.PrincipalConfigureRequest{
		"no gateway":   {PrincipalSub: "ana", Code: "com.notion/mcp"},
		"no principal": {GatewayID: ids.New[ids.GatewayKind](), Code: "com.notion/mcp"},
		"no code":      {GatewayID: ids.New[ids.GatewayKind](), PrincipalSub: "ana"},
	}
	for name, in := range cases {
		if _, err := linker.LinkFor(context.Background(), in); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: want a validation error, got %v", name, err)
		}
	}
	if _, err := appstore.NewPrincipalConfigureLinker(nil); err == nil {
		t.Fatal("want an error without a ticket minter")
	}
}
