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
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
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

type configureInstalls struct {
	item *installationdomain.Installation
}

func (c configureInstalls) FindByID(
	_ context.Context,
	_ ids.GatewayID,
	_ string,
	id ids.InstallationID,
) (*installationdomain.Installation, error) {
	if c.item == nil || c.item.ID != id {
		return nil, installationdomain.ErrNotFound
	}
	return c.item, nil
}

func TestPrincipalConfigureLinkerMintsAgainstTheStorePath(t *testing.T) {
	minter := &fakeConfigureMinter{id: "cfg-1"}
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.snowflake/mcp"},
	}
	installID := ids.New[ids.InstallationKind]()
	linker, err := appstore.NewPrincipalConfigureLinker(
		minter,
		connectRegistries{items: []*registrydomain.Registry{registry}},
		configureInstalls{item: &installationdomain.Installation{
			ID: installID, GatewayID: gw, PrincipalSub: "ana", CatalogCode: "com.snowflake/mcp", RegistryID: registry.ID,
		}},
		connectGrants{},
		nil,
		connectGateway(gw, gatewaydomain.StoreModeOpen),
	)
	if err != nil {
		t.Fatalf("NewPrincipalConfigureLinker: %v", err)
	}
	link, err := linker.LinkFor(context.Background(), appstore.PrincipalConfigureRequest{
		GatewayID:    gw,
		PrincipalSub: " ana ",
		Code:         " com.snowflake/mcp ",
		InstanceID:   " " + installID.String() + " ",
		Groups:       []string{"eng"},
	})
	if err != nil {
		t.Fatalf("LinkFor: %v", err)
	}
	if link.Ticket != "cfg-1" || link.ConsumerPath != "/store/mcp" {
		t.Fatalf("link: %+v", link)
	}
	if minter.got.principalSub != "ana" || minter.got.code != "com.snowflake/mcp" ||
		minter.got.instanceID != installID.String() || minter.got.consumerPath != "/store/mcp" ||
		minter.got.gatewayID != gw || len(minter.got.groups) != 1 {
		t.Fatalf("minted %+v", minter.got)
	}
}

func TestPrincipalConfigureLinkerValidatesItsInput(t *testing.T) {
	linker, _ := appstore.NewPrincipalConfigureLinker(&fakeConfigureMinter{id: "cfg-2"}, connectRegistries{}, nil, nil, nil, nil)
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
	if _, err := appstore.NewPrincipalConfigureLinker(nil, connectRegistries{}, nil, nil, nil, nil); err == nil {
		t.Fatal("want an error without a ticket minter")
	}
}

func TestPrincipalConfigureLinkerEnforcesStoreAccess(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	registry := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.snowflake/mcp"},
	}
	grant, err := storeaccessdomain.New(gw, "com.snowflake/mcp", registry.ID, []string{"eng"}, nil)
	if err != nil {
		t.Fatalf("new grant: %v", err)
	}
	cases := map[string]struct {
		mode   string
		grants []*storeaccessdomain.Grant
		want   error
	}{
		"store closed": {mode: gatewaydomain.StoreModeNone, want: appstore.ErrStoreClosed},
		"ungranted":    {mode: gatewaydomain.StoreModeCurated, want: commonerrors.ErrForbidden},
		"group grant":  {mode: gatewaydomain.StoreModeCurated, grants: []*storeaccessdomain.Grant{grant}},
	}
	for name, tc := range cases {
		minter := &fakeConfigureMinter{id: "cfg-" + name}
		linker, _ := appstore.NewPrincipalConfigureLinker(
			minter,
			connectRegistries{items: []*registrydomain.Registry{registry}},
			nil,
			connectGrants{items: tc.grants},
			nil,
			connectGateway(gw, tc.mode),
		)
		_, err := linker.LinkFor(context.Background(), appstore.PrincipalConfigureRequest{
			GatewayID: gw, PrincipalSub: "ana", Code: "com.snowflake/mcp", Groups: []string{"eng"},
		})
		if tc.want == nil {
			if err != nil || minter.got.code == "" {
				t.Fatalf("%s: want ticket, got %v", name, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func TestPrincipalConfigureLinkerRejectsTheNamedInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	disabled := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: false,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.snowflake/mcp"},
	}
	ungranted := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.snowflake/mcp"},
	}
	granted := &registrydomain.Registry{
		ID: ids.New[ids.RegistryKind](), GatewayID: gw, Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{Code: "com.snowflake/mcp"},
	}
	grant, err := storeaccessdomain.New(gw, "com.snowflake/mcp", granted.ID, nil, []string{"ana"})
	if err != nil {
		t.Fatalf("new grant: %v", err)
	}
	cases := map[string]struct {
		registry *registrydomain.Registry
		want     error
	}{
		"disabled":    {registry: disabled, want: appstore.ErrServerDisabled},
		"not granted": {registry: ungranted, want: commonerrors.ErrForbidden},
	}
	for name, tc := range cases {
		minter := &fakeConfigureMinter{id: "must-not-mint"}
		installID := ids.New[ids.InstallationKind]()
		linker, _ := appstore.NewPrincipalConfigureLinker(
			minter,
			connectRegistries{items: []*registrydomain.Registry{disabled, ungranted, granted}},
			configureInstalls{item: &installationdomain.Installation{
				ID: installID, GatewayID: gw, PrincipalSub: "ana", CatalogCode: "com.snowflake/mcp", RegistryID: tc.registry.ID,
			}},
			connectGrants{items: []*storeaccessdomain.Grant{grant}},
			nil,
			connectGateway(gw, gatewaydomain.StoreModeCurated),
		)
		_, err := linker.LinkFor(context.Background(), appstore.PrincipalConfigureRequest{
			GatewayID: gw, PrincipalSub: "ana", Code: "com.snowflake/mcp", InstanceID: installID.String(),
		})
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v, got %v", name, tc.want, err)
		}
		if minter.got.code != "" {
			t.Fatalf("%s: minted a ticket: %+v", name, minter.got)
		}
	}
}
