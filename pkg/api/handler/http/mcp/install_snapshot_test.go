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
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
)

type fakeStreamInstalls struct {
	rows []*installationdomain.Installation
}

func (f *fakeStreamInstalls) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return f.rows, nil
}
func (f *fakeStreamInstalls) Upsert(context.Context, *installationdomain.Installation) error {
	return nil
}
func (f *fakeStreamInstalls) Find(context.Context, ids.GatewayID, string, string) (*installationdomain.Installation, error) {
	return nil, installationdomain.ErrNotFound
}
func (f *fakeStreamInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeStreamInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeStreamInstalls) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

func TestInstallSnapshot_ReflectsInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	installs := &fakeStreamInstalls{rows: []*installationdomain.Installation{
		{GatewayID: gw, PrincipalSub: "ana", CatalogCode: "com.notion/mcp", Status: installationdomain.StatusInstalled, UpdatedAt: now},
	}}
	h := NewHandler(nil, nil, nil, WithInstallations(installs))
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: gw}}

	parts := h.installSnapshot(context.Background(), rc, &identity.Principal{Subject: "ana"})
	if len(parts) != 1 || !strings.HasPrefix(parts[0], "in:com.notion/mcp:") {
		t.Fatalf("install must appear in the watched snapshot, got %v", parts)
	}
	// A later install of the same code at a new time yields a different string, so
	// the polling stream sees a change and pushes tools/list_changed.
	installs.rows[0].UpdatedAt = now.Add(time.Minute)
	next := h.installSnapshot(context.Background(), rc, &identity.Principal{Subject: "ana"})
	if next[0] == parts[0] {
		t.Fatal("a changed install must change the snapshot string")
	}
}

func TestInstallSnapshot_EmptyWhenNotWired(t *testing.T) {
	h := NewHandler(nil, nil, nil) // no WithInstallations
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{GatewayID: ids.New[ids.GatewayKind]()}}
	if parts := h.installSnapshot(context.Background(), rc, &identity.Principal{Subject: "ana"}); parts != nil {
		t.Fatalf("no installs repo must yield an empty snapshot, got %v", parts)
	}
}
