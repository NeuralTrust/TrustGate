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
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// fakeSurfaceScoper stands in for the Store scoper: it exposes whatever
// registries the test says the caller may currently see, and records the
// principal it was asked as.
type fakeSurfaceScoper struct {
	exposed []*registrydomain.Registry
	err     error
	subject string
}

func (f *fakeSurfaceScoper) Scope(ctx context.Context, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error) {
	if p := identity.PrincipalFromContext(ctx); p != nil {
		f.subject = p.Subject
	}
	if f.err != nil {
		return nil, f.err
	}
	scoped := *rc
	scoped.Registries = f.exposed
	return &scoped, nil
}

func surfaceReg(name string) *registrydomain.Registry {
	return &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: name}
}

func TestSurfaceWatcher_LoadSurface_ChangesWhenAccessIsRevoked(t *testing.T) {
	notion, linear := surfaceReg("Notion"), surfaceReg("Linear")
	scoper := &fakeSurfaceScoper{exposed: []*registrydomain.Registry{linear, notion}}
	w := NewSurfaceWatcher(nil, nil, WithSurfaceScoper(scoper)).(*surfaceWatcher)
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: ids.New[ids.GatewayKind]()}}
	ana := &identity.Principal{Subject: "ana"}

	before, err := w.loadSurface(context.Background(), rc, ana)
	if err != nil {
		t.Fatalf("loadSurface: %v", err)
	}
	if len(before) != 2 || !strings.HasPrefix(before[0], "sf:") {
		t.Fatalf("both exposed registries must be fingerprinted, got %v", before)
	}
	// The scoper runs as the caller.
	if scoper.subject != "ana" {
		t.Fatalf("scoper must see the principal, got %q", scoper.subject)
	}
	// Sorted: the repository order must not read as a change.
	scoper.exposed = []*registrydomain.Registry{notion, linear}
	same, _ := w.loadSurface(context.Background(), rc, ana)
	if strings.Join(same, "|") != strings.Join(before, "|") {
		t.Fatalf("reordering must not change the snapshot: %v vs %v", same, before)
	}
	// An admin revokes Notion: the install row is unchanged, the surface shrinks,
	// and the fingerprint must move so the stream pushes tools/list_changed.
	scoper.exposed = []*registrydomain.Registry{linear}
	after, _ := w.loadSurface(context.Background(), rc, ana)
	if len(after) != 1 || strings.Join(after, "|") == strings.Join(before, "|") {
		t.Fatalf("revocation must change the snapshot: before=%v after=%v", before, after)
	}
}

func TestSurfaceWatcher_WatchSnapshotIncludesSurface(t *testing.T) {
	scoper := &fakeSurfaceScoper{exposed: []*registrydomain.Registry{surfaceReg("Notion")}}
	w := NewSurfaceWatcher(nil, nil, WithSurfaceScoper(scoper))
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: ids.New[ids.GatewayKind]()}}

	snapshot := w.WatchSnapshot(context.Background(), rc, &identity.Principal{Subject: "ana"})
	if !strings.Contains(snapshot, "sf:") {
		t.Fatalf("watch snapshot must carry the Store surface, got %q", snapshot)
	}
}

func TestSurfaceWatcher_LoadSurface_NoScoperOrError(t *testing.T) {
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: ids.New[ids.GatewayKind]()}}
	ana := &identity.Principal{Subject: "ana"}

	plain := NewSurfaceWatcher(nil, nil).(*surfaceWatcher)
	if parts, err := plain.loadSurface(context.Background(), rc, ana); err != nil || len(parts) != 0 {
		t.Fatalf("no scoper must mean no surface parts, got %v %v", parts, err)
	}

	failing := NewSurfaceWatcher(nil, nil, WithSurfaceScoper(&fakeSurfaceScoper{err: errors.New("boom"), exposed: nil})).(*surfaceWatcher)
	if _, err := failing.loadSurface(context.Background(), rc, ana); err == nil {
		t.Fatal("a scoper error must surface so the snapshot is not cached")
	}
	// A transient scoper error yields an empty, uncached snapshot (like the
	// credential and installation lookups), never a poisoned cache entry.
	if got := failing.WatchSnapshot(context.Background(), rc, ana); got != "" {
		t.Fatalf("failed load must yield an empty snapshot, got %q", got)
	}
}
