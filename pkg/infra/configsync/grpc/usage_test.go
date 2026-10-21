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
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type fakeUsage struct {
	mu        sync.Mutex
	exhausted map[string]usagedomain.TenantState
	asOf      int64
	subs      []chan struct{}
	notReady  bool
}

func (f *fakeUsage) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.notReady
}

func (f *fakeUsage) becomeReady() {
	f.mu.Lock()
	f.notReady = false
	subs := append([]chan struct{}(nil), f.subs...)
	f.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func newFakeUsage(states ...usagedomain.TenantState) *fakeUsage {
	f := &fakeUsage{exhausted: map[string]usagedomain.TenantState{}}
	for _, s := range states {
		f.exhausted[s.TenantID] = s
		f.asOf = max(f.asOf, s.Version)
	}
	return f
}

func (f *fakeUsage) SnapshotAll() usagedomain.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := usagedomain.Snapshot{AsOfVersion: f.asOf}
	for _, s := range f.exhausted {
		out.Exhausted = append(out.Exhausted, s)
	}
	return out
}

func (f *fakeUsage) SnapshotTenant(tenantID string) usagedomain.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := usagedomain.Snapshot{AsOfVersion: f.asOf}
	if s, ok := f.exhausted[tenantID]; ok && tenantID != "" {
		out.Exhausted = append(out.Exhausted, s)
	}
	return out
}

func (f *fakeUsage) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	return ch, func() {}
}

func (f *fakeUsage) exhaust(s usagedomain.TenantState) {
	f.mu.Lock()
	f.exhausted[s.TenantID] = s
	f.asOf = max(f.asOf, s.Version)
	subs := append([]chan struct{}(nil), f.subs...)
	f.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func exhaustedState(t *testing.T, tenant string, version int64) usagedomain.TenantState {
	t.Helper()
	s, err := usagedomain.NewTenantState(tenant, usagedomain.StatusExhausted, usagedomain.ReasonFreeLimitReached, version)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return s
}

func openSync(t *testing.T, srv snapshotpb.ConfigSyncServer) snapshotpb.ConfigSync_SyncClient {
	t.Helper()
	lis, _ := newBufServer(t, srv)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := snapshotpb.NewConfigSyncClient(conn).Sync(ctx)
	if err != nil {
		t.Fatalf("open sync: %v", err)
	}
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{InstanceId: "dp-1"}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return stream
}

func recvUsage(t *testing.T, stream snapshotpb.ConfigSync_SyncClient) *snapshotpb.UsageSnapshot {
	t.Helper()
	type result struct {
		msg *snapshotpb.ServerMessage
		err error
	}
	got := make(chan result, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil || msg.GetUsage() != nil {
				got <- result{msg, err}
				return
			}
		}
	}()
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("recv: %v", r.err)
		}
		return r.msg.GetUsage()
	case <-time.After(2 * time.Second):
		t.Fatal("no usage message")
		return nil
	}
}

func TestSyncPushesUsageOnConnectAndOnChange(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 4))
	stream := openSync(t, NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)))

	first := recvUsage(t, stream)
	if first.GetAsOfVersion() != 4 || len(first.GetExhausted()) != 1 || first.GetExhausted()[0].GetTenantId() != "tenant-a" ||
		first.GetExhausted()[0].GetReason() != snapshotpb.UsageReason_USAGE_REASON_FREE_LIMIT_REACHED {
		t.Fatalf("first usage = %v", first)
	}
	usage.exhaust(exhaustedState(t, "tenant-b", 6))
	second := recvUsage(t, stream)
	if second.GetAsOfVersion() != 6 || len(second.GetExhausted()) != 2 {
		t.Fatalf("second usage = %v", second)
	}
}

func TestSyncWithoutUsageSendsNoUsage(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	stream := openSync(t, NewService(NewHub(discardLogger(), nil), src, discardLogger()))
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if msg.GetUsage() != nil || msg.GetNotice().GetVersion() != "v1" {
		t.Fatalf("first message = %v, want only the version notice", msg)
	}
}

type failingGateways struct{}

func (failingGateways) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	return nil, errors.New("postgres down")
}

func TestUsageSnapshotForScopes(t *testing.T) {
	gwA := tenantGateway(t, "tenant-a")
	gateways := &fakeGateways{byID: map[ids.GatewayID]*gatewaydomain.Gateway{gwA.ID: gwA}}
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 3), exhaustedState(t, "tenant-b", 5))
	unknownGateway, err := ids.NewV7[ids.GatewayKind]()
	if err != nil {
		t.Fatalf("id: %v", err)
	}

	tests := []struct {
		name     string
		gateways GatewayResolver
		scope    string
		wantSent bool
		want     []string
	}{
		{name: "in-cluster data plane gets every tenant", gateways: gateways, scope: "", wantSent: true, want: []string{"tenant-a", "tenant-b"}},
		{name: "hybrid gateway scope gets only its tenant", gateways: gateways, scope: gwA.ID.String(), wantSent: true, want: []string{"tenant-a"}},
		{name: "tenant-wide scope gets that tenant", gateways: gateways, scope: "tenant-b", wantSent: true, want: []string{"tenant-b"}},
		{name: "unknown gateway gets nobody", gateways: gateways, scope: unknownGateway.String(), wantSent: true},
		{name: "unresolvable scope sends nothing", gateways: failingGateways{}, scope: gwA.ID.String(), wantSent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, tt.gateways))
			msg, sent := svc.usageSnapshotFor(context.Background(), tt.scope)
			if sent != tt.wantSent {
				t.Fatalf("sent = %v, want %v", sent, tt.wantSent)
			}
			if !sent {
				return
			}
			got := map[string]bool{}
			for _, e := range msg.GetUsage().GetExhausted() {
				got[e.GetTenantId()] = true
			}
			if len(got) != len(tt.want) {
				t.Fatalf("tenants = %v, want %v", got, tt.want)
			}
			for _, id := range tt.want {
				if !got[id] {
					t.Fatalf("tenants = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestClientWatchIgnoresUsageMessages(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 1))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), WithUsage(usage, nil)))
	client := dialClient(t, lis, "dp-1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	version, err := client.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if version != "v1" {
		t.Fatalf("Watch = %q, want the notice that follows the usage message", version)
	}
}

func TestSyncHoldsUsageUntilTheSourceIsReady(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 2))
	usage.notReady = true
	hub := NewHub(discardLogger(), nil)
	stream := openSync(t, NewService(hub, &fakeSource{}, discardLogger(), WithUsage(usage, nil)))

	got := make(chan *snapshotpb.ServerMessage, 1)
	go func() {
		msg, err := stream.Recv()
		if err == nil {
			got <- msg
		}
	}()
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	select {
	case msg := <-got:
		t.Fatalf("sent %v before the usage list was ready", msg)
	case <-time.After(200 * time.Millisecond):
	}

	usage.becomeReady()
	select {
	case msg := <-got:
		if len(msg.GetUsage().GetExhausted()) != 1 {
			t.Fatalf("usage = %v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no usage message once the source became ready")
	}
}

type recordingSink struct {
	mu        sync.Mutex
	snapshots []usagedomain.Snapshot
}

func (r *recordingSink) ApplySnapshot(snapshot usagedomain.Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots = append(r.snapshots, snapshot)
}

func (r *recordingSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.snapshots)
}

func TestClientWatchFeedsUsageToTheSink(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 7))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), WithUsage(usage, nil)))
	client := dialClient(t, lis, "dp-1")
	sink := &recordingSink{}
	client.SetUsageSink(sink)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.Watch(ctx); err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("sink got %d snapshots, want 1", sink.count())
	}
	got := sink.snapshots[0]
	if got.AsOfVersion != 7 || len(got.Exhausted) != 1 || got.Exhausted[0].TenantID != "tenant-a" ||
		got.Exhausted[0].Reason != usagedomain.ReasonFreeLimitReached {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestClientWatchReceivesAUsageMessageAboveTheDefaultLimit(t *testing.T) {
	const tenants = 100_000
	states := make([]usagedomain.TenantState, 0, tenants)
	for i := range tenants {
		states = append(states, exhaustedState(t, fmt.Sprintf("00000000-0000-4000-8000-%012d", i), int64(i+1)))
	}
	usage := newFakeUsage(states...)
	msg, _ := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)).usageSnapshotFor(context.Background(), "")
	if size := proto.Size(msg); size <= 4<<20 {
		t.Fatalf("usage message is %d bytes; the test needs one above 4 MiB", size)
	}
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), WithUsage(usage, nil)))
	client := dialClient(t, lis, "dp-1")
	sink := &recordingSink{}
	client.SetUsageSink(sink)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.Watch(ctx); err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if sink.count() != 1 || len(sink.snapshots[0].Exhausted) != tenants {
		t.Fatalf("sink got %d snapshots, want one with every tenant", sink.count())
	}
}
