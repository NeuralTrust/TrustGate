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

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakeEveryoneReader struct {
	item *storeaccessdomain.Everyone
	err  error
}

func (f *fakeEveryoneReader) GetEveryone(context.Context, ids.GatewayID) (*storeaccessdomain.Everyone, error) {
	return f.item, f.err
}

func everyoneGranting(t *testing.T, gw ids.GatewayID, mode string, codes ...string) *storeaccessdomain.Everyone {
	t.Helper()
	grants := make([]storeaccessdomain.EveryoneGrant, 0, len(codes))
	for _, c := range codes {
		grants = append(grants, storeaccessdomain.EveryoneGrant{CatalogCode: c})
	}
	e, err := storeaccessdomain.NewEveryone(gw, mode, grants, []string{"contractors"})
	if err != nil {
		t.Fatalf("NewEveryone: %v", err)
	}
	return e
}

func TestModeResolverRaisesToEveryone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	policies := &fakePolicies{items: []*storeaccessdomain.Policy{
		policy(gw, storeaccessdomain.PrincipalGroup, "sales", gatewaydomain.StoreModeCurated),
		policy(gw, storeaccessdomain.PrincipalGroup, "sre", gatewaydomain.StoreModeNone),
	}}
	r := NewModeResolver(NewAccessReader(nil, policies, &fakeEveryoneReader{item: everyoneGranting(t, gw, gatewaydomain.StoreModeOpen)}))

	if got := ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Subject: "ana", Groups: []string{"sales"}, Fallback: gatewaydomain.StoreModeCurated}); got != gatewaydomain.StoreModeOpen {
		t.Fatalf("Everyone open must raise a curated group, got %q", got)
	}
	if got := ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Subject: "bob", Groups: []string{"sre"}, Fallback: gatewaydomain.StoreModeOpen}); got != gatewaydomain.StoreModeNone {
		t.Fatalf("a group on none does not reach Everyone, got %q", got)
	}
	if got := ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Groups: []string{"contractors"}, Fallback: gatewaydomain.StoreModeCurated}); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("a group key of an excluded group does not reach Everyone, got %q", got)
	}
}

func TestModeResolverIgnoresEveryoneOnReadError(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	r := NewModeResolver(NewAccessReader(nil, &fakePolicies{}, &fakeEveryoneReader{err: errors.New("db down")}))
	if got := ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Subject: "ana", Groups: []string{"sales"}, Fallback: gatewaydomain.StoreModeCurated}); got != gatewaydomain.StoreModeCurated {
		t.Fatalf("a failed Everyone read must be ignored, got %q", got)
	}
}

func TestLoadGrantSetAddsEveryone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	everyone := &fakeEveryoneReader{item: everyoneGranting(t, gw, gatewaydomain.StoreModeCurated, "github")}

	set, err := loadGrantSet(context.Background(), NewAccessReader(grantsOf(), &fakePolicies{}, everyone), gw)
	if err != nil || !set.CodeAllows("github", []string{"sales"}, "ana") {
		t.Fatalf("an access reader must add Everyone's servers, got err %v", err)
	}
	plain, err := loadPlainGrantSet(context.Background(), NewAccessReader(grantsOf(), &fakePolicies{}, everyone), gw)
	if err != nil || plain.CodeAllows("github", []string{"sales"}, "ana") {
		t.Fatalf("the plain set must hold explicit grants only, got err %v", err)
	}
	failed, err := loadGrantSet(context.Background(), NewAccessReader(grantsOf(), &fakePolicies{err: errors.New("db down")}, everyone), gw)
	if err != nil || failed.CodeAllows("github", []string{"sales"}, "ana") {
		t.Fatalf("without policies nobody reaches Everyone, got err %v", err)
	}
	bare, err := loadGrantSet(context.Background(), grantsOf(), gw)
	if err != nil || bare.CodeAllows("github", []string{"sales"}, "ana") {
		t.Fatalf("a grants-only reader adds no Everyone, got err %v", err)
	}
}

func TestInstallEveryoneServerSkipsApproval(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	reader := NewAccessReader(grantsOf(), &fakePolicies{}, &fakeEveryoneReader{item: everyoneGranting(t, gw, gatewaydomain.StoreModeCurated, "github")})

	installs := &fakeInstalls{}
	res, err := newInstallerWithGrants(t, regs, installs, reader).Install(context.Background(), req(gw, "github", "sales"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Pending || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("a server Everyone grants must install without approval, got %+v", res)
	}

	excluded, err := newInstallerWithGrants(t, regs, &fakeInstalls{}, reader).Install(context.Background(), req(gw, "github", "contractors"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !excluded.Pending || excluded.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("an excluded caller must still ask, got %+v", excluded)
	}
}
