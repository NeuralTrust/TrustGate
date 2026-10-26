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
	"sort"
	"sync"
	"testing"
	"time"

	usageapp "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type fakeUsage struct {
	mu        sync.Mutex
	states    map[string]usagedomain.TenantState
	changedAt map[string]uint64
	seq       uint64
	asOf      int64
	subs      []chan struct{}
	notReady  bool
	// incomplete makes the lists carry no as_of version, like a control
	// plane that has only read its cache.
	incomplete bool
}

func (f *fakeUsage) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.notReady
}

func (f *fakeUsage) becomeReady() {
	f.mu.Lock()
	f.notReady = false
	f.mu.Unlock()
	f.notify()
}

func newFakeUsage(states ...usagedomain.TenantState) *fakeUsage {
	f := &fakeUsage{states: map[string]usagedomain.TenantState{}, changedAt: map[string]uint64{}}
	for _, s := range states {
		f.writeLocked(s)
	}
	return f
}

func (f *fakeUsage) writeLocked(s usagedomain.TenantState) {
	f.states[s.TenantID] = s
	f.asOf = max(f.asOf, s.Version)
	f.seq++
	f.changedAt[s.TenantID] = f.seq
}

func (f *fakeUsage) SnapshotAll() usagedomain.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := usagedomain.Snapshot{AsOfVersion: f.listAsOfLocked()}
	for _, s := range f.states {
		if s.Exhausted() {
			out.Exhausted = append(out.Exhausted, s)
		}
	}
	return out
}

func (f *fakeUsage) SnapshotTenant(tenantID string) usagedomain.Snapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := usagedomain.Snapshot{AsOfVersion: f.listAsOfLocked()}
	if s, ok := f.states[tenantID]; ok && tenantID != "" && s.Exhausted() {
		out.Exhausted = append(out.Exhausted, s)
	}
	return out
}

func (f *fakeUsage) listAsOfLocked() int64 {
	if f.incomplete {
		return 0
	}
	return f.asOf
}

func (f *fakeUsage) Cursor() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seq
}

func (f *fakeUsage) ChangesSince(cursor uint64) ([]usagedomain.TenantState, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []usagedomain.TenantState
	for tenant, at := range f.changedAt {
		if at > cursor {
			out = append(out, f.states[tenant])
		}
	}
	sort.Slice(out, func(i, j int) bool { return f.changedAt[out[i].TenantID] < f.changedAt[out[j].TenantID] })
	return out, max(cursor, f.seq)
}

func (f *fakeUsage) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	return ch, func() {}
}

func (f *fakeUsage) exhaust(s usagedomain.TenantState) {
	f.set(s)
}

func (f *fakeUsage) set(states ...usagedomain.TenantState) {
	f.mu.Lock()
	for _, s := range states {
		f.writeLocked(s)
	}
	f.mu.Unlock()
	f.notify()
}

func (f *fakeUsage) notify() {
	f.mu.Lock()
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
	return openSyncWith(t, srv, &snapshotpb.Hello{InstanceId: "dp-1", AcceptsUsage: true})
}

func openSyncWith(t *testing.T, srv snapshotpb.ConfigSyncServer, hello *snapshotpb.Hello) snapshotpb.ConfigSync_SyncClient {
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
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: hello}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return stream
}

func recvUsage(t *testing.T, stream snapshotpb.ConfigSync_SyncClient) *snapshotpb.UsageSnapshot {
	t.Helper()
	msg := recvUsageMessage(t, stream)
	if msg.GetUsage() == nil {
		t.Fatalf("got %v, want a usage list", msg)
	}
	return msg.GetUsage()
}

func recvUsageMessage(t *testing.T, stream snapshotpb.ConfigSync_SyncClient) *snapshotpb.ServerMessage {
	t.Helper()
	type result struct {
		msg *snapshotpb.ServerMessage
		err error
	}
	got := make(chan result, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil || msg.GetUsage() != nil || msg.GetUsageChanges() != nil {
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
		return r.msg
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
		compiled bool
		wantSent bool
		want     []string
	}{
		{name: "in-cluster data plane gets every tenant", gateways: gateways, scope: "", wantSent: true, want: []string{"tenant-a", "tenant-b"}},
		{name: "hybrid gateway scope gets only its tenant", gateways: gateways, scope: gwA.ID.String(), wantSent: true, want: []string{"tenant-a"}},
		{name: "tenant-wide scope gets that tenant", gateways: gateways, scope: "tenant-b", wantSent: true, want: []string{"tenant-b"}},
		{name: "unknown gateway sends nothing", gateways: gateways, scope: unknownGateway.String(), wantSent: false},
		{name: "deleted gateway whose snapshot is still compiled sends nothing", gateways: gateways, scope: unknownGateway.String(), compiled: true, wantSent: false},
		{name: "gateway scope without a resolver sends nothing", gateways: nil, scope: gwA.ID.String(), wantSent: false},
		{name: "unresolvable scope sends nothing", gateways: failingGateways{}, scope: gwA.ID.String(), wantSent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &fakeSource{}
			if tt.compiled {
				src.set([]byte("scoped"), "v1")
			}
			svc := NewService(NewHub(discardLogger(), nil), src, discardLogger(), WithUsage(usage, tt.gateways))
			msgs, sent := svc.newUsageStream(tt.scope, false).next(context.Background())
			if sent != tt.wantSent {
				t.Fatalf("sent = %v, want %v", sent, tt.wantSent)
			}
			if !sent {
				return
			}
			if len(msgs) != 1 {
				t.Fatalf("messages = %v, want one list", msgs)
			}
			got := map[string]bool{}
			for _, e := range msgs[0].GetUsage().GetExhausted() {
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
	changes   [][]usagedomain.TenantState
}

func (r *recordingSink) ApplyChanges(states []usagedomain.TenantState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, states)
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
	msgs, _ := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)).newUsageStream("", true).next(context.Background())
	if size := proto.Size(msgs[0]); size <= 4<<20 {
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

func TestUsageSnapshotFromProtoKeepsListedTenantsBlocked(t *testing.T) {
	got := usageSnapshotFromProto(&snapshotpb.UsageSnapshot{
		AsOfVersion: 12,
		Exhausted: []*snapshotpb.TenantUsage{
			{TenantId: "zero-version", Reason: snapshotpb.UsageReason_USAGE_REASON_WALLET_EMPTY},
			{TenantId: "unknown-reason", Reason: snapshotpb.UsageReason(99), Version: 4},
			{TenantId: "", Version: 5},
		},
	})
	byTenant := map[string]usagedomain.TenantState{}
	for _, st := range got.Exhausted {
		byTenant[st.TenantID] = st
	}
	if len(byTenant) != 2 {
		t.Fatalf("exhausted = %+v, want the two entries with a tenant", got.Exhausted)
	}
	if st := byTenant["zero-version"]; st.Version != 12 || !st.Exhausted() {
		t.Fatalf("zero-version = %+v, want exhausted as of the snapshot", st)
	}
	if st := byTenant["unknown-reason"]; st.Reason != usagedomain.ReasonWalletEmpty {
		t.Fatalf("unknown-reason = %+v, want wallet_empty", st)
	}
}

func TestSyncSendsOwedUsageOnceTheScopeResolves(t *testing.T) {
	gw := tenantGateway(t, "tenant-a")
	gateways := &flakyGateways{gw: gw, failing: true}
	tenantScope := gw.ID
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 3))
	src := &fakeSource{}
	hub := NewHub(discardLogger(), nil)
	svc := NewService(hub, src, discardLogger(), WithUsage(usage, gateways))

	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer(grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &recordingStream{ServerStream: ss, ctx: WithScope(ss.Context(), tenantScope.String())})
	}))
	snapshotpb.RegisterConfigSyncServer(gsrv, svc)
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := snapshotpb.NewConfigSyncClient(conn).Sync(ctx)
	if err != nil {
		t.Fatalf("open sync: %v", err)
	}
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{InstanceId: "dp-1", AcceptsUsage: true}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}

	got := make(chan *snapshotpb.ServerMessage, 4)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			got <- msg
		}
	}()
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	select {
	case msg := <-got:
		t.Fatalf("sent %v while the gateway lookup fails", msg)
	case <-time.After(200 * time.Millisecond):
	}

	gateways.recover()
	src.set([]byte("scoped"), "v2")
	hub.Broadcast("v2")
	var sawNotice bool
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg := <-got:
			if msg.GetNotice() != nil {
				sawNotice = true
				continue
			}
			if u := msg.GetUsage(); u != nil {
				if !sawNotice || len(u.GetExhausted()) != 1 || u.GetExhausted()[0].GetTenantId() != "tenant-a" {
					t.Fatalf("usage = %v (after notice: %v), want the tenant's list after the notice", u, sawNotice)
				}
				return
			}
		case <-deadline:
			t.Fatal("the owed usage list never followed the notice")
		}
	}
}

type flakyGateways struct {
	mu      sync.Mutex
	gw      *gatewaydomain.Gateway
	failing bool
}

func (f *flakyGateways) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		return nil, errors.New("postgres down")
	}
	if id == f.gw.ID {
		return f.gw, nil
	}
	return nil, gatewaydomain.ErrNotFound
}

func (f *flakyGateways) recover() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = false
}

func TestSyncSendsNoUsageToADataPlaneThatDoesNotAcceptIt(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 1))
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger(), WithUsage(usage, nil)))
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
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{InstanceId: "old-dp"}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if msg.GetUsage() != nil || msg.GetNotice().GetVersion() != "v1" {
		t.Fatalf("first message = %v, want only the version notice for a data plane that does not accept usage", msg)
	}
	usage.exhaust(exhaustedState(t, "tenant-b", 2))
	got := make(chan *snapshotpb.ServerMessage, 1)
	go func() {
		if m, err := stream.Recv(); err == nil {
			got <- m
		}
	}()
	select {
	case m := <-got:
		t.Fatalf("sent %v to a data plane that does not accept usage", m)
	case <-time.After(200 * time.Millisecond):
	}
}

func healthyState(t *testing.T, tenant string, version int64) usagedomain.TenantState {
	t.Helper()
	s, err := usagedomain.NewTenantState(tenant, usagedomain.StatusHealthy, usagedomain.ReasonNone, version)
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return s
}

func changedTenants(t *testing.T, msg *snapshotpb.ServerMessage) map[string]snapshotpb.UsageStatus {
	t.Helper()
	if msg.GetUsageChanges() == nil {
		t.Fatalf("got %v, want usage changes", msg)
	}
	out := map[string]snapshotpb.UsageStatus{}
	for _, st := range msg.GetUsageChanges().GetStates() {
		out[st.GetTenantId()] = st.GetStatus()
	}
	return out
}

func TestSyncSendsADataPlaneThatTakesChangesOnlyWhatChanged(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 4))
	stream := openSyncWith(t, NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)),
		&snapshotpb.Hello{InstanceId: "dp-1", AcceptsUsage: true, AcceptsUsageChanges: true})

	if first := recvUsage(t, stream); first.GetAsOfVersion() != 4 || len(first.GetExhausted()) != 1 {
		t.Fatalf("first usage = %v, want the full list", first)
	}

	usage.exhaust(exhaustedState(t, "tenant-b", 6))
	got := changedTenants(t, recvUsageMessage(t, stream))
	if len(got) != 1 || got["tenant-b"] != snapshotpb.UsageStatus_USAGE_STATUS_EXHAUSTED {
		t.Fatalf("changes = %v, want only tenant-b exhausted", got)
	}

	usage.set(healthyState(t, "tenant-a", 4))
	got = changedTenants(t, recvUsageMessage(t, stream))
	if len(got) != 1 || got["tenant-a"] != snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY {
		t.Fatalf("changes = %v, want tenant-a unblocked at its own version", got)
	}
}

func TestUsageStreamSendsListsUntilOneIsComplete(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 4))
	usage.incomplete = true
	stream := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)).newUsageStream("", true)
	ctx := context.Background()

	if msgs, _ := stream.next(ctx); len(msgs) != 1 || msgs[0].GetUsage() == nil || msgs[0].GetUsage().GetAsOfVersion() != 0 {
		t.Fatalf("first = %v, want a list with no as_of version", msgs)
	}
	usage.set(exhaustedState(t, "tenant-b", 5))
	if msgs, _ := stream.next(ctx); len(msgs) != 1 || msgs[0].GetUsage() == nil {
		t.Fatalf("second = %v, want another list while none is complete", msgs)
	}

	usage.mu.Lock()
	usage.incomplete = false
	usage.mu.Unlock()
	usage.set(healthyState(t, "tenant-b", 7))
	msgs, _ := stream.next(ctx)
	if len(msgs) != 1 || msgs[0].GetUsage().GetAsOfVersion() != 7 || len(msgs[0].GetUsage().GetExhausted()) != 1 {
		t.Fatalf("third = %v, want the complete list, which unblocks what it leaves out", msgs)
	}

	usage.set(exhaustedState(t, "tenant-c", 8))
	msgs, _ = stream.next(ctx)
	if got := changedTenants(t, msgs[0]); len(got) != 1 || got["tenant-c"] != snapshotpb.UsageStatus_USAGE_STATUS_EXHAUSTED {
		t.Fatalf("changes = %v, want only tenant-c once a complete list went out", got)
	}
}

type countingGateways struct {
	fakeGateways
	mu    sync.Mutex
	calls int
}

func (c *countingGateways) FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.fakeGateways.FindByID(ctx, id)
}

func TestUsageStreamScopedToAGatewayGetsOnlyItsTenantsChanges(t *testing.T) {
	gw := tenantGateway(t, "tenant-a")
	gateways := &countingGateways{fakeGateways: fakeGateways{byID: map[ids.GatewayID]*gatewaydomain.Gateway{gw.ID: gw}}}
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 3), exhaustedState(t, "tenant-b", 5))
	stream := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, gateways)).newUsageStream(gw.ID.String(), true)
	ctx := context.Background()

	msgs, _ := stream.next(ctx)
	if len(msgs) != 1 || len(msgs[0].GetUsage().GetExhausted()) != 1 || msgs[0].GetUsage().GetExhausted()[0].GetTenantId() != "tenant-a" {
		t.Fatalf("first = %v, want the list with only tenant-a", msgs)
	}
	usage.set(healthyState(t, "tenant-b", 6))
	if msgs, ok := stream.next(ctx); len(msgs) != 0 || !ok {
		t.Fatalf("sent %v (ok %v) for another tenant's change, want nothing owed", msgs, ok)
	}
	usage.set(healthyState(t, "tenant-a", 7))
	msgs, _ = stream.next(ctx)
	if got := changedTenants(t, msgs[0]); len(got) != 1 || got["tenant-a"] != snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY {
		t.Fatalf("changes = %v, want tenant-a unblocked", got)
	}
	if gateways.calls != 1 {
		t.Fatalf("gateway looked up %d times, want once per stream", gateways.calls)
	}
}

func TestUsageStreamScopedToATenantGetsOnlyItsChanges(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 3), exhaustedState(t, "tenant-b", 5))
	stream := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)).newUsageStream("tenant-b", true)
	ctx := context.Background()

	if msgs, _ := stream.next(ctx); len(msgs) != 1 || len(msgs[0].GetUsage().GetExhausted()) != 1 {
		t.Fatalf("first = %v, want the list with only tenant-b", msgs)
	}
	usage.set(healthyState(t, "tenant-a", 6), healthyState(t, "tenant-b", 6))
	msgs, _ := stream.next(ctx)
	if got := changedTenants(t, msgs[0]); len(got) != 1 || got["tenant-b"] != snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY {
		t.Fatalf("changes = %v, want only tenant-b", got)
	}
}

func TestUsageStreamSplitsALargeBurstOfChanges(t *testing.T) {
	usage := newFakeUsage(exhaustedState(t, "seed", 1))
	stream := NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger(), WithUsage(usage, nil)).newUsageStream("", true)
	ctx := context.Background()
	stream.next(ctx)

	burst := make([]usagedomain.TenantState, 0, 2*maxUsageChangesPerMessage+1)
	for i := range cap(burst) {
		burst = append(burst, exhaustedState(t, fmt.Sprintf("tenant-%d", i), int64(i+2)))
	}
	usage.set(burst...)
	msgs, _ := stream.next(ctx)
	total := 0
	for _, msg := range msgs {
		n := len(msg.GetUsageChanges().GetStates())
		if n > maxUsageChangesPerMessage {
			t.Fatalf("message carries %d changes, want at most %d", n, maxUsageChangesPerMessage)
		}
		total += n
	}
	if len(msgs) != 3 || total != len(burst) {
		t.Fatalf("got %d messages with %d changes, want 3 with %d", len(msgs), total, len(burst))
	}
}

func TestClientWatchFeedsUsageChangesToTheSink(t *testing.T) {
	src := &fakeSource{}
	usage := newFakeUsage(exhaustedState(t, "tenant-a", 7))
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), WithUsage(usage, nil)))
	client := dialClient(t, lis, "dp-1")
	sink := &recordingSink{}
	client.SetUsageSink(sink)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Watch(ctx)
		done <- err
	}()
	eventually(t, func() bool { return sink.count() == 1 }, "no usage list on connect")
	usage.set(healthyState(t, "tenant-a", 8))
	eventually(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.changes) == 1
	}, "no usage changes after the list")
	sink.mu.Lock()
	got := sink.changes[0]
	sink.mu.Unlock()
	if len(got) != 1 || got[0].TenantID != "tenant-a" || got[0].Exhausted() || got[0].Version != 8 {
		t.Fatalf("changes = %+v, want tenant-a healthy at 8", got)
	}
	src.set([]byte("payload"), "v1")
	hub.Broadcast("v1")
	if err := <-done; err != nil {
		t.Fatalf("Watch: %v", err)
	}
}

func TestUsageChangesFromProtoDropsWhatItCannotApply(t *testing.T) {
	got := usageChangesFromProto(&snapshotpb.UsageChanges{States: []*snapshotpb.TenantUsageState{
		{TenantId: "blocked", Status: snapshotpb.UsageStatus_USAGE_STATUS_EXHAUSTED, Reason: snapshotpb.UsageReason_USAGE_REASON_WALLET_EMPTY, Version: 3},
		{TenantId: "unblocked", Status: snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY, Version: 4},
		{TenantId: "no-status", Reason: snapshotpb.UsageReason_USAGE_REASON_WALLET_EMPTY, Version: 5},
		{TenantId: "no-version", Status: snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY},
		{Status: snapshotpb.UsageStatus_USAGE_STATUS_HEALTHY, Version: 6},
	}})
	if len(got) != 2 || got[0].TenantID != "blocked" || !got[0].Exhausted() || got[1].TenantID != "unblocked" || got[1].Exhausted() {
		t.Fatalf("states = %+v, want only blocked and unblocked", got)
	}
}

type nopStateCache struct{}

func (nopStateCache) SaveAll(context.Context, []usagedomain.TenantState) error { return nil }

func (nopStateCache) LoadAll(context.Context) ([]usagedomain.TenantState, error) { return nil, nil }

type countingSink struct {
	*usageapp.Enforcement
	mu        sync.Mutex
	snapshots int
	changes   int
}

func (c *countingSink) ApplySnapshot(snapshot usagedomain.Snapshot) {
	c.mu.Lock()
	c.snapshots++
	c.mu.Unlock()
	c.Enforcement.ApplySnapshot(snapshot)
}

func (c *countingSink) ApplyChanges(states []usagedomain.TenantState) {
	c.mu.Lock()
	c.changes++
	c.mu.Unlock()
	c.Enforcement.ApplyChanges(states)
}

func (c *countingSink) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshots, c.changes
}

func TestUsageFromTheStoreReachesTheDataPlaneAsChanges(t *testing.T) {
	ctx := context.Background()
	store := usageapp.NewStore(nopStateCache{}, discardLogger(), time.Second)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	must(store.ApplySnapshot(ctx, []usagedomain.TenantState{exhaustedState(t, "tenant-a", 5), exhaustedState(t, "tenant-b", 5)}, 5))

	src := &fakeSource{}
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger(), WithUsage(store, nil)))
	client := dialClient(t, lis, "dp-1")
	sink := &countingSink{Enforcement: usageapp.NewEnforcement()}
	client.SetUsageSink(sink)

	watchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Watch(watchCtx)
		done <- err
	}()
	blocked := func(tenant string) bool {
		_, ok := sink.Exhausted(tenant)
		return ok
	}
	eventually(t, func() bool { return sink.Received() && blocked("tenant-a") && blocked("tenant-b") }, "the first list never reached the data plane")

	must(store.ApplySnapshot(ctx, []usagedomain.TenantState{exhaustedState(t, "tenant-b", 5)}, 5))
	eventually(t, func() bool { return !blocked("tenant-a") }, "the unblock at the same version never reached the data plane")
	must(store.Apply(ctx, []usagedomain.TenantState{exhaustedState(t, "tenant-c", 6)}))
	eventually(t, func() bool { return blocked("tenant-c") }, "the new block never reached the data plane")

	if !blocked("tenant-b") {
		t.Fatal("tenant-b unblocked by changes that did not mention it")
	}
	if snapshots, changes := sink.counts(); snapshots != 1 || changes != 2 {
		t.Fatalf("data plane got %d lists and %d change messages, want 1 list then 2 changes", snapshots, changes)
	}
	src.set([]byte("payload"), "v1")
	hub.Broadcast("v1")
	if err := <-done; err != nil {
		t.Fatalf("Watch: %v", err)
	}
}
