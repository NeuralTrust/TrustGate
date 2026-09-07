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

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// recordingInstaller captures the request the on-behalf installer produced.
type recordingInstaller struct {
	got     *InstallRequest
	subject string
	groups  []string
}

func (r *recordingInstaller) Install(ctx context.Context, in InstallRequest) (*InstallResult, error) {
	r.got = &in
	if p := identity.PrincipalFromContext(ctx); p != nil {
		r.subject = p.Subject
		r.groups = principalGroups(p)
	}
	return &InstallResult{Code: in.Code, Status: installationdomain.StatusInstalled}, nil
}
func (r *recordingInstaller) Instances(context.Context, ids.GatewayID, string, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (r *recordingInstaller) Uninstall(context.Context, ids.GatewayID, string, string, string) error {
	return nil
}

type fakeGateways struct{ gw *gatewaydomain.Gateway }

func (f fakeGateways) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return f.gw, nil
}

// fakePolicyReader serves the per-principal levels the resolver consults.
type fakePolicyReader struct{ items []*storeaccessdomain.Policy }

func (f fakePolicyReader) ListPoliciesByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	return f.items, nil
}

func gatewayWithMode(t *testing.T, mode string) *gatewaydomain.Gateway {
	t.Helper()
	return &gatewaydomain.Gateway{
		ID:       ids.New[ids.GatewayKind](),
		Metadata: gatewaydomain.WithStoreMode(nil, mode),
	}
}

func TestPrincipalInstaller_ActsAsThePrincipalWithTheGatewayDefault(t *testing.T) {
	gw := gatewayWithMode(t, gatewaydomain.StoreModeOpen)
	rec := &recordingInstaller{}
	p, err := NewPrincipalInstaller(rec, NewModeResolver(fakePolicyReader{}), fakeGateways{gw: gw})
	if err != nil {
		t.Fatalf("NewPrincipalInstaller: %v", err)
	}
	res, err := p.InstallFor(context.Background(), OnBehalfInstallRequest{
		GatewayID: gw.ID, PrincipalSub: " ana ", Code: "github", Groups: []string{"eng", " ", "Engineering"}, Actor: "admin@corp",
	})
	if err != nil {
		t.Fatalf("InstallFor: %v", err)
	}
	if res.Code != "github" {
		t.Fatalf("result: %+v", res)
	}
	if rec.got.PrincipalSub != "ana" || rec.got.InstalledBy != "admin@corp" || !rec.got.OpenMode {
		t.Fatalf("request should run as ana under the open default, got %+v", rec.got)
	}
	if rec.subject != "ana" || len(rec.groups) != 2 {
		t.Fatalf("installer must see the principal in context: sub=%q groups=%v", rec.subject, rec.groups)
	}
}

func TestPrincipalInstaller_PolicyBeatsGatewayDefault(t *testing.T) {
	gw := gatewayWithMode(t, gatewaydomain.StoreModeOpen)
	own, _ := storeaccessdomain.NewPolicy(gw.ID, storeaccessdomain.PrincipalUser, "ana", gatewaydomain.StoreModeCurated)
	rec := &recordingInstaller{}
	p, _ := NewPrincipalInstaller(rec, NewModeResolver(fakePolicyReader{items: []*storeaccessdomain.Policy{own}}), fakeGateways{gw: gw})
	if _, err := p.InstallFor(context.Background(), OnBehalfInstallRequest{GatewayID: gw.ID, PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("InstallFor: %v", err)
	}
	if rec.got.OpenMode {
		t.Fatalf("ana's own curated policy must win over the open default")
	}
	if rec.got.InstalledBy != "ana" {
		t.Fatalf("without an actor the principal is the installer, got %q", rec.got.InstalledBy)
	}
}

func TestPrincipalInstaller_NoneIsClosed(t *testing.T) {
	gw := gatewayWithMode(t, gatewaydomain.StoreModeOpen)
	own, _ := storeaccessdomain.NewPolicy(gw.ID, storeaccessdomain.PrincipalGroup, "eng", gatewaydomain.StoreModeNone)
	rec := &recordingInstaller{}
	p, _ := NewPrincipalInstaller(rec, NewModeResolver(fakePolicyReader{items: []*storeaccessdomain.Policy{own}}), fakeGateways{gw: gw})
	_, err := p.InstallFor(context.Background(), OnBehalfInstallRequest{GatewayID: gw.ID, PrincipalSub: "ana", Code: "github", Groups: []string{"eng"}})
	if !errors.Is(err, ErrStoreClosed) || !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("want ErrStoreClosed (conflict), got %v", err)
	}
	if rec.got != nil {
		t.Fatalf("nothing must be installed or requested under None")
	}
}

func TestPrincipalInstaller_WithoutGatewayFailsClosedToCurated(t *testing.T) {
	rec := &recordingInstaller{}
	p, _ := NewPrincipalInstaller(rec, nil, nil)
	if _, err := p.InstallFor(context.Background(), OnBehalfInstallRequest{GatewayID: ids.New[ids.GatewayKind](), PrincipalSub: "ana", Code: "github"}); err != nil {
		t.Fatalf("InstallFor: %v", err)
	}
	if rec.got.OpenMode {
		t.Fatalf("unknown default must not open the Store")
	}
	// Sanity: the context helper the resolver relies on round-trips a gateway.
	gw := gatewayWithMode(t, gatewaydomain.StoreModeOpen)
	if got, ok := appgateway.FromContext(appgateway.WithGateway(context.Background(), gw)); !ok || got != gw {
		t.Fatalf("WithGateway/FromContext mismatch")
	}
}

func TestPrincipalInstaller_Validates(t *testing.T) {
	p, _ := NewPrincipalInstaller(&recordingInstaller{}, nil, nil)
	gw := ids.New[ids.GatewayKind]()
	for _, in := range []OnBehalfInstallRequest{
		{PrincipalSub: "ana", Code: "github"},
		{GatewayID: gw, Code: "github"},
		{GatewayID: gw, PrincipalSub: "ana"},
	} {
		if _, err := p.InstallFor(context.Background(), in); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("want validation error for %+v, got %v", in, err)
		}
	}
	if _, err := NewPrincipalInstaller(nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable without an installer, got %v", err)
	}
}
