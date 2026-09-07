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
	"context"
	"errors"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// fakeSurfaceScoper stands in for the Store scoper: it exposes whatever
// registries the test says the caller may currently see, and records the
// context it was asked with.
type fakeSurfaceScoper struct {
	exposed []*registrydomain.Registry
	err     error
	subject string
	gateway *gatewaydomain.Gateway
}

func (f *fakeSurfaceScoper) Scope(ctx context.Context, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error) {
	if p := identity.PrincipalFromContext(ctx); p != nil {
		f.subject = p.Subject
	}
	f.gateway, _ = appgateway.FromContext(ctx)
	if f.err != nil {
		return nil, f.err
	}
	scoped := *rc
	scoped.Registries = f.exposed
	return &scoped, nil
}

func reg(name string) *registrydomain.Registry {
	return &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: name}
}

func TestSurfaceSnapshot_ChangesWhenAccessIsRevoked(t *testing.T) {
	notion, linear := reg("Notion"), reg("Linear")
	scoper := &fakeSurfaceScoper{exposed: []*registrydomain.Registry{linear, notion}}
	h := NewHandler(NewRPCGateway(nil, nil, nil).WithStoreScoper(scoper), nil, nil)
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: gw.ID}}
	ana := &identity.Principal{Subject: "ana"}

	before := h.surfaceSnapshot(context.Background(), rc, ana, gw)
	if len(before) != 2 || !strings.HasPrefix(before[0], "sf:") {
		t.Fatalf("both exposed registries must be fingerprinted, got %v", before)
	}
	// The scoper runs as the caller, with the gateway for the live mode decision.
	if scoper.subject != "ana" || scoper.gateway != gw {
		t.Fatalf("scoper must see the principal and gateway: sub=%q gw=%v", scoper.subject, scoper.gateway)
	}
	// Sorted: the repository order must not read as a change.
	scoper.exposed = []*registrydomain.Registry{notion, linear}
	if same := h.surfaceSnapshot(context.Background(), rc, ana, gw); strings.Join(same, "|") != strings.Join(before, "|") {
		t.Fatalf("reordering must not change the snapshot: %v vs %v", same, before)
	}
	// An admin revokes Notion: the install row is unchanged, the surface shrinks,
	// the snapshot string changes and the stream pushes tools/list_changed.
	scoper.exposed = []*registrydomain.Registry{linear}
	after := h.surfaceSnapshot(context.Background(), rc, ana, gw)
	if len(after) != 1 || strings.Join(after, "|") == strings.Join(before, "|") {
		t.Fatalf("revoking a server must change the snapshot, got %v", after)
	}
}

func TestSurfaceSnapshot_QuietWhenUnwiredOrFailing(t *testing.T) {
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: ids.New[ids.GatewayKind]()}}
	ana := &identity.Principal{Subject: "ana"}
	// No gateway / no scoper: nothing to watch.
	if parts := NewHandler(nil, nil, nil).surfaceSnapshot(context.Background(), rc, ana, nil); parts != nil {
		t.Fatalf("no scoper must yield an empty snapshot, got %v", parts)
	}
	if parts := NewHandler(NewRPCGateway(nil, nil, nil), nil, nil).surfaceSnapshot(context.Background(), rc, ana, nil); parts != nil {
		t.Fatalf("unwired scoper must yield an empty snapshot, got %v", parts)
	}
	// A transient scoper error reads as "no change", never as a refresh storm.
	failing := &fakeSurfaceScoper{err: errors.New("boom")}
	if parts := NewHandler(NewRPCGateway(nil, nil, nil).WithStoreScoper(failing), nil, nil).surfaceSnapshot(context.Background(), rc, ana, nil); parts != nil {
		t.Fatalf("scoper error must yield an empty snapshot, got %v", parts)
	}
	// No principal: nothing to scope.
	if parts := NewHandler(NewRPCGateway(nil, nil, nil).WithStoreScoper(&fakeSurfaceScoper{}), nil, nil).surfaceSnapshot(context.Background(), rc, nil, nil); parts != nil {
		t.Fatalf("no principal must yield an empty snapshot, got %v", parts)
	}
}
