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
	"encoding/json"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func dialPinnedTools(t *testing.T, f pinnedFixture) *PinnedToolsClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	snapshotpb.RegisterPinnedToolsServer(gsrv, f.svc)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewPinnedToolsClient(conn, discardLogger())
}

func mustCandidate(t *testing.T, name, desc, schema string) registrydomain.ToolCandidate {
	t.Helper()
	c, err := registrydomain.NewToolCandidate(name, desc, json.RawMessage(schema))
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	return c
}

// The server recomputes the fingerprint from the wire fields; it must land on
// exactly the one the data plane computed, or a recorded row could never match
// the (name, fingerprint) the data plane screens by. Schemas with odd key order,
// numeric literals and a non-JSON value cover the canonicalisation corners.
func TestPinnedToolsClient_ServerFingerprintMatchesTheClients(t *testing.T) {
	f := newPinnedFixture(t)
	client := dialPinnedTools(t, f)

	cands := []registrydomain.ToolCandidate{
		mustCandidate(t, "plain", "d", `{"type":"object"}`),
		mustCandidate(t, "reordered", "ünï \"quoted\" <b>", `{"b":1.0,"a":[3,2],"c":{"z":null,"y":1e3}}`),
		mustCandidate(t, "empty-schema", "", ``),
		mustCandidate(t, "invalid-schema", "d", `{not json`),
	}
	if err := client.Record(context.Background(), f.acme.ID, f.pinned, cands); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(f.store.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(f.store.calls))
	}
	got := f.store.calls[0].tools
	for i, want := range cands {
		if got[i].ToolRef != want.ToolRef {
			t.Errorf("%s: server ref %+v != client ref %+v", want.Name, got[i].ToolRef, want.ToolRef)
		}
	}
}

func TestPinnedToolsClient_SplitsLargeBatches(t *testing.T) {
	f := newPinnedFixture(t)
	client := dialPinnedTools(t, f)

	total := MaxPendingToolsPerCall*2 + 1
	cands := make([]registrydomain.ToolCandidate, 0, total)
	for i := range total {
		cands = append(cands, mustCandidate(t, "t"+strings.Repeat("0", 3)+string(rune('A'+i%26))+string(rune('a'+i/26)), "d", `{}`))
	}
	if err := client.Record(context.Background(), f.acme.ID, f.pinned, cands); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(f.store.calls) != 3 {
		t.Fatalf("calls = %d, want 3 batches", len(f.store.calls))
	}
}

func TestPinnedToolsClient_RegistryOfAnotherGatewayIsIgnored(t *testing.T) {
	f := newPinnedFixture(t)
	client := dialPinnedTools(t, f)
	unknown, _ := ids.NewV7[ids.GatewayKind]()
	err := client.Record(context.Background(), unknown, f.pinned, []registrydomain.ToolCandidate{mustCandidate(t, "a", "d", `{}`)})
	if err != nil {
		t.Fatalf("a registry of another gateway is ignored, not an error: %v", err)
	}
	if len(f.store.calls) != 0 {
		t.Fatal("nothing must be written for a registry that is not the gateway's")
	}
}

type unimplementedPinned struct {
	snapshotpb.UnimplementedPinnedToolsServer
	calls int
}

func (u *unimplementedPinned) RecordPending(context.Context, *snapshotpb.RecordPendingToolsRequest) (*snapshotpb.RecordPendingToolsResponse, error) {
	u.calls++
	return nil, status.Error(codes.Unimplemented, "old control plane")
}

// An older control plane answers Unimplemented. The client must not fail every
// discovery: it reports success (so the recorder keeps its keys), stops calling
// for the back-off window and probes again afterwards.
func TestPinnedToolsClient_BacksOffWhenTheControlPlaneIsOld(t *testing.T) {
	srv := &unimplementedPinned{}
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	snapshotpb.RegisterPinnedToolsServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := NewPinnedToolsClient(conn, discardLogger())
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	gw, _ := ids.NewV7[ids.GatewayKind]()
	reg, _ := ids.NewV7[ids.RegistryKind]()
	cands := []registrydomain.ToolCandidate{mustCandidate(t, "a", "d", `{}`)}

	if err := client.Record(context.Background(), gw, reg, cands); err != nil {
		t.Fatalf("Unimplemented must not surface as an error: %v", err)
	}
	for range 5 {
		if err := client.Record(context.Background(), gw, reg, cands); err != nil {
			t.Fatalf("Record during back-off: %v", err)
		}
	}
	if srv.calls != 1 {
		t.Fatalf("calls = %d during the back-off window, want 1", srv.calls)
	}

	now = now.Add(unimplementedBackoff + time.Second)
	_ = client.Record(context.Background(), gw, reg, cands)
	if srv.calls != 2 {
		t.Fatalf("calls = %d after the window, want one probe (2)", srv.calls)
	}
}
