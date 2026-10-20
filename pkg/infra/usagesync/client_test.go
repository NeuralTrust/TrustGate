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

package usagesync

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	usagev1 "github.com/NeuralTrust/TrustGate/pkg/infra/usagesync/proto/usage/v1"
)

type recordingSink struct {
	mu        sync.Mutex
	watermark int64
	exhausted map[string]domain.TenantState
	snapshots int
}

func newRecordingSink() *recordingSink {
	return &recordingSink{exhausted: map[string]domain.TenantState{}}
}

func (r *recordingSink) Apply(_ context.Context, states []domain.TenantState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range states {
		if s.Exhausted() {
			r.exhausted[s.TenantID] = s
		} else {
			delete(r.exhausted, s.TenantID)
		}
		r.watermark = max(r.watermark, s.Version)
	}
	return nil
}

func (r *recordingSink) ApplySnapshot(_ context.Context, exhausted []domain.TenantState, asOf int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots++
	r.exhausted = map[string]domain.TenantState{}
	for _, s := range exhausted {
		r.exhausted[s.TenantID] = s
	}
	r.watermark = max(r.watermark, asOf)
	return nil
}

func (r *recordingSink) Watermark() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.watermark
}

func (r *recordingSink) has(tenant string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.exhausted[tenant]
	return ok
}

type fakeServer struct {
	usagev1.UnimplementedUsageSyncServiceServer
	mu       sync.Mutex
	hellos   []int64
	acks     []int64
	sessions []func(usagev1.UsageSyncService_SyncServer) error
}

func (f *fakeServer) Sync(stream usagev1.UsageSyncService_SyncServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.hellos = append(f.hellos, first.GetHello().GetLastVersion())
	var script func(usagev1.UsageSyncService_SyncServer) error
	if len(f.sessions) > 0 {
		script, f.sessions = f.sessions[0], f.sessions[1:]
	}
	f.mu.Unlock()
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			if ack := msg.GetAck(); ack != nil {
				f.mu.Lock()
				f.acks = append(f.acks, ack.GetVersion())
				f.mu.Unlock()
			}
		}
	}()
	if script == nil {
		<-stream.Context().Done()
		return nil
	}
	return script(stream)
}

func (f *fakeServer) helloVersions() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.hellos...)
}

func usageState(tenant string, exhausted bool, version int64) *usagev1.UsageState {
	st := &usagev1.UsageState{TenantId: tenant, Status: usagev1.UsageStatus_USAGE_STATUS_HEALTHY, Version: version}
	if exhausted {
		st.Status = usagev1.UsageStatus_USAGE_STATUS_EXHAUSTED
		st.Reason = usagev1.ExhaustionReason_EXHAUSTION_REASON_WALLET_EMPTY
	}
	return st
}

func startClient(t *testing.T, srv *fakeServer, sink StateSink) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	usagev1.RegisterUsageSyncServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", append([]grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, streamDialOptions()...)...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := newClient(conn, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = client.Close() })
	go client.Run(ctx)
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestClientAppliesSnapshotAndChangesAndResyncsOnReconnect(t *testing.T) {
	srv := &fakeServer{sessions: []func(usagev1.UsageSyncService_SyncServer) error{
		func(stream usagev1.UsageSyncService_SyncServer) error {
			if err := stream.Send(&usagev1.SyncResponse{Message: &usagev1.SyncResponse_Snapshot{Snapshot: &usagev1.Snapshot{
				Exhausted: []*usagev1.UsageState{usageState("a", true, 5), {TenantId: "", Version: 1}}, AsOfVersion: 5,
			}}}); err != nil {
				return err
			}
			if err := stream.Send(&usagev1.SyncResponse{Message: &usagev1.SyncResponse_Change{Change: usageState("b", true, 7)}}); err != nil {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			return nil
		},
		func(stream usagev1.UsageSyncService_SyncServer) error {
			if err := stream.Send(&usagev1.SyncResponse{Message: &usagev1.SyncResponse_Snapshot{Snapshot: &usagev1.Snapshot{
				Exhausted: []*usagev1.UsageState{usageState("b", true, 7)}, AsOfVersion: 9,
			}}}); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		},
	}}
	sink := newRecordingSink()
	startClient(t, srv, sink)

	eventually(t, func() bool { return sink.has("a") && sink.has("b") }, "first snapshot and change never applied")
	eventually(t, func() bool { return len(srv.helloVersions()) == 2 }, "client never reconnected")
	if got := srv.helloVersions(); got[0] != 0 || got[1] != 7 {
		t.Fatalf("hello versions = %v, want [0 7]: the reconnect must send the watermark", got)
	}
	eventually(t, func() bool { return !sink.has("a") && sink.has("b") && sink.Watermark() == 9 }, "resync snapshot never applied")
	srv.mu.Lock()
	acks := append([]int64(nil), srv.acks...)
	srv.mu.Unlock()
	if len(acks) < 2 || acks[0] != 5 || acks[1] != 7 {
		t.Fatalf("acks = %v, want 5 then 7", acks)
	}
}

// A snapshot above gRPC's 4 MiB default must still be received: the list of
// exhausted tenants travels in one message.
func TestClientReceivesASnapshotAboveTheDefaultMessageLimit(t *testing.T) {
	const tenants = 100_000
	exhausted := make([]*usagev1.UsageState, 0, tenants)
	for i := range tenants {
		exhausted = append(exhausted, usageState(fmt.Sprintf("00000000-0000-4000-8000-%012d", i), true, int64(i+1)))
	}
	snapshot := &usagev1.SyncResponse{Message: &usagev1.SyncResponse_Snapshot{Snapshot: &usagev1.Snapshot{Exhausted: exhausted, AsOfVersion: tenants}}}
	if size := proto.Size(snapshot); size <= 4<<20 {
		t.Fatalf("snapshot is %d bytes; the test needs one above 4 MiB", size)
	}
	srv := &fakeServer{sessions: []func(usagev1.UsageSyncService_SyncServer) error{
		func(stream usagev1.UsageSyncService_SyncServer) error {
			if err := stream.Send(snapshot); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		},
	}}
	sink := newRecordingSink()
	startClient(t, srv, sink)
	eventually(t, func() bool { return sink.Watermark() == tenants }, "the large snapshot was not applied")
	if !sink.has("00000000-0000-4000-8000-000000099999") {
		t.Fatal("the last tenant of the large snapshot is missing")
	}
}
