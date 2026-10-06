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

package grpc

import (
	"context"
	"strings"
	"testing"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ snapshotpb.PinnedToolsServer = (*PinnedToolsService)(nil)

type memRegistries map[ids.RegistryID]*registrydomain.Registry

func (m memRegistries) FindByID(_ context.Context, id ids.RegistryID) (*registrydomain.Registry, error) {
	if r, ok := m[id]; ok {
		return r, nil
	}
	return nil, registrydomain.ErrNotFound
}

type pendingCall struct {
	gateway  ids.GatewayID
	registry ids.RegistryID
	tools    []registrydomain.ToolCandidate
}

// memPending records what the store was asked to insert.
type memPending struct {
	calls   []pendingCall
	dropAll bool
}

func (m *memPending) UpsertPending(
	_ context.Context, g ids.GatewayID, r ids.RegistryID, tools []registrydomain.ToolCandidate,
) (int, int, error) {
	m.calls = append(m.calls, pendingCall{g, r, tools})
	if m.dropAll {
		return 0, len(tools), nil
	}
	return len(tools), 0, nil
}

type pinnedFixture struct {
	svc     *PinnedToolsService
	store   *memPending
	acme    *gatewaydomain.Gateway
	globex  *gatewaydomain.Gateway
	pinned  ids.RegistryID // acme, pinned
	auto    ids.RegistryID // acme, auto
	foreign ids.RegistryID // globex, pinned
}

func newPinnedFixture(t *testing.T) pinnedFixture {
	t.Helper()
	f := pinnedFixture{
		store:  &memPending{},
		acme:   tenantGateway(t, "acme"),
		globex: tenantGateway(t, "globex"),
	}
	regs := memRegistries{}
	add := func(gw ids.GatewayID, policy registrydomain.ToolPolicy) ids.RegistryID {
		id, err := ids.NewV7[ids.RegistryKind]()
		if err != nil {
			t.Fatalf("registry id: %v", err)
		}
		regs[id] = registrydomain.Rehydrate(registrydomain.RehydrateParams{
			ID: id, GatewayID: gw, Name: "r", Type: registrydomain.TypeMCP, ToolPolicy: policy,
		})
		return id
	}
	f.pinned = add(f.acme.ID, registrydomain.ToolPolicyPinned)
	f.auto = add(f.acme.ID, registrydomain.ToolPolicyAuto)
	f.foreign = add(f.globex.ID, registrydomain.ToolPolicyPinned)
	f.svc = NewPinnedToolsService(regs, f.store, &fakeGateways{
		byID: map[ids.GatewayID]*gatewaydomain.Gateway{f.acme.ID: f.acme, f.globex.ID: f.globex},
	}, discardLogger())
	return f
}

func pendingReq(gw ids.GatewayID, reg ids.RegistryID, tools ...*snapshotpb.PendingTool) *snapshotpb.RecordPendingToolsRequest {
	return &snapshotpb.RecordPendingToolsRequest{GatewayId: gw.String(), RegistryId: reg.String(), Tools: tools}
}

func tool(name string) *snapshotpb.PendingTool {
	return &snapshotpb.PendingTool{Name: name, Description: "d", InputSchema: []byte(`{"type":"object"}`)}
}

func TestPinnedToolsService_RecordsPendingWithServerSideFingerprint(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())

	resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tool("a")))
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if resp.GetRecorded() != 1 || len(f.store.calls) != 1 {
		t.Fatalf("recorded=%d calls=%d, want 1/1", resp.GetRecorded(), len(f.store.calls))
	}
	got := f.store.calls[0].tools[0]
	want := registrydomain.Fingerprint("a", "d", []byte(`{"type":"object"}`))
	if got.Fingerprint != want {
		t.Fatalf("fingerprint = %s, want the server's own computation %s", got.Fingerprint, want)
	}
}

// The wire message has no fingerprint field at all, so there is nothing a hostile
// caller could forge; this pins that property.
func TestPinnedToolsService_WireCarriesNoFingerprint(t *testing.T) {
	fields := (&snapshotpb.PendingTool{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		if strings.Contains(strings.ToLower(string(fields.Get(i).Name())), "fingerprint") {
			t.Fatalf("PendingTool must not carry %q: the server derives it", fields.Get(i).Name())
		}
	}
}

// A data plane scoped to one tenant must not write rows for another tenant's
// gateway, whatever ids it puts on the wire.
func TestPinnedToolsService_CrossGatewayIsDenied(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())

	_, err := f.svc.RecordPending(ctx, pendingReq(f.globex.ID, f.foreign, tool("a")))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if len(f.store.calls) != 0 {
		t.Fatalf("a refused call wrote %d times", len(f.store.calls))
	}

	unknown, _ := ids.NewV7[ids.GatewayKind]()
	_, err = f.svc.RecordPending(ctx, pendingReq(unknown, f.foreign, tool("a")))
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown gateway: code = %v, want NotFound", status.Code(err))
	}
}

func TestPinnedToolsService_TenantScopeReachesItsOwnGateways(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), "acme")
	if _, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tool("a"))); err != nil {
		t.Fatalf("tenant-scoped RecordPending: %v", err)
	}
	if len(f.store.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(f.store.calls))
	}
}

// A caller scoped to its own gateway that names another gateway's registry id
// under its own gateway id writes nothing and learns nothing.
func TestPinnedToolsService_RegistryOfAnotherGatewayIsIgnored(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())

	resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.foreign, tool("a")))
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if resp.GetRecorded() != 0 || len(f.store.calls) != 0 {
		t.Fatalf("recorded=%d calls=%d, want nothing written", resp.GetRecorded(), len(f.store.calls))
	}
}

func TestPinnedToolsService_NonPinnedOrUnknownRegistryIsIgnored(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())
	missing, _ := ids.NewV7[ids.RegistryKind]()

	for name, reg := range map[string]ids.RegistryID{"auto": f.auto, "unknown": missing} {
		resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, reg, tool("a")))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if resp.GetRecorded() != 0 || len(f.store.calls) != 0 {
			t.Fatalf("%s: wrote rows for a registry that is not pinned", name)
		}
	}
}

func TestPinnedToolsService_RefusesACallAboveTheLimit(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())

	tools := make([]*snapshotpb.PendingTool, MaxPendingToolsPerCall+1)
	for i := range tools {
		tools[i] = tool("t" + strings.Repeat("x", i%5) + string(rune('a'+i%26)))
	}
	_, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tools...))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
	if len(f.store.calls) != 0 {
		t.Fatal("a refused call must write nothing")
	}
	if _, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tools[:MaxPendingToolsPerCall]...)); err != nil {
		t.Fatalf("exactly the limit must pass: %v", err)
	}
}

// One bad tool must not keep the good ones from being recorded.
func TestPinnedToolsService_SkipsInvalidToolsAndRecordsTheRest(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())

	resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned,
		tool("good-1"),
		tool(""),
		tool(strings.Repeat("n", MaxPendingToolNameBytes+1)),
		&snapshotpb.PendingTool{Name: "big", Description: strings.Repeat("d", MaxPendingToolBytes)},
		&snapshotpb.PendingTool{Name: "nul", Description: "x\x00y"},
		tool("good-2"),
	))
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if resp.GetAccepted() != 2 || resp.GetSkipped() != 4 || resp.GetRecorded() != 2 {
		t.Fatalf("accepted=%d skipped=%d recorded=%d, want 2/4/2", resp.GetAccepted(), resp.GetSkipped(), resp.GetRecorded())
	}
	if len(f.store.calls) != 1 || len(f.store.calls[0].tools) != 2 {
		t.Fatalf("store calls = %+v", f.store.calls)
	}
}

func TestPinnedToolsService_OnlyInvalidToolsWritesNothing(t *testing.T) {
	f := newPinnedFixture(t)
	ctx := WithScope(context.Background(), f.acme.ID.String())
	resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tool("")))
	if err != nil || resp.GetSkipped() != 1 || len(f.store.calls) != 0 {
		t.Fatalf("resp=%v err=%v calls=%d", resp, err, len(f.store.calls))
	}
}

func TestPinnedToolsService_RejectsBadIDs(t *testing.T) {
	f := newPinnedFixture(t)
	_, err := f.svc.RecordPending(context.Background(), &snapshotpb.RecordPendingToolsRequest{GatewayId: "nope", RegistryId: f.pinned.String()})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad gateway id: code = %v", status.Code(err))
	}
	_, err = f.svc.RecordPending(context.Background(), &snapshotpb.RecordPendingToolsRequest{GatewayId: f.acme.ID.String(), RegistryId: "nope"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad registry id: code = %v", status.Code(err))
	}
}

func TestPinnedToolsService_ReportsWhatTheCapDropped(t *testing.T) {
	f := newPinnedFixture(t)
	f.store.dropAll = true
	ctx := WithScope(context.Background(), f.acme.ID.String())
	resp, err := f.svc.RecordPending(ctx, pendingReq(f.acme.ID, f.pinned, tool("a"), tool("b")))
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if resp.GetRecorded() != 0 || resp.GetDropped() != 2 {
		t.Fatalf("recorded=%d dropped=%d, want 0/2", resp.GetRecorded(), resp.GetDropped())
	}
}
