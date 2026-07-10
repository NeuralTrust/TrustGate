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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

var (
	_ configsync.ConfigFetcher    = (*Client)(nil)
	_ configsync.StreamTransport  = (*Client)(nil)
	_ snapshotpb.ConfigSyncServer = (*Service)(nil)
)

type fakeSource struct {
	mu      sync.Mutex
	raw     []byte
	version string
	ok      bool
}

func (f *fakeSource) SnapshotFor(string) ([]byte, string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw, f.version, f.ok
}

func (f *fakeSource) set(raw []byte, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw, f.version, f.ok = raw, version, true
}

type fakeServer struct {
	snapshotpb.UnimplementedConfigSyncServer
	getSnapshot func(*snapshotpb.GetSnapshotRequest, snapshotpb.ConfigSync_GetSnapshotServer) error
}

func (f *fakeServer) GetSnapshot(req *snapshotpb.GetSnapshotRequest, stream snapshotpb.ConfigSync_GetSnapshotServer) error {
	return f.getSnapshot(req, stream)
}

func newBufServer(t *testing.T, srv snapshotpb.ConfigSyncServer) (*bufconn.Listener, *grpc.Server) {
	t.Helper()
	lis := bufconn.Listen(4 << 20)
	gsrv := grpc.NewServer()
	snapshotpb.RegisterConfigSyncServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(func() { gsrv.Stop() })
	return lis, gsrv
}

func dialClient(t *testing.T, lis *bufconn.Listener, instanceID string) *Client {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := newClient(conn, instanceID, discardLogger())
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestClient_FetchReassemblesMultipleChunks(t *testing.T) {
	src := &fakeSource{}
	raw := bytes.Repeat([]byte("abcd"), (3*snapshotChunkSize)/4+3)
	src.set(raw, "v-big")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger()))
	client := dialClient(t, lis, "dp-1")

	got, version, notModified, err := client.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if notModified {
		t.Fatal("notModified = true, want false")
	}
	if version != "v-big" {
		t.Fatalf("version = %q, want v-big", version)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("reassembled body mismatch: len %d != %d", len(got), len(raw))
	}
}

func TestClient_FetchNotModified(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger()))
	client := dialClient(t, lis, "dp-1")

	_, _, notModified, err := client.Fetch(context.Background(), "v1")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !notModified {
		t.Fatal("notModified = false, want true when applied == current")
	}
}

func TestClient_FetchRejectsLengthMismatch(t *testing.T) {
	fake := &fakeServer{getSnapshot: func(_ *snapshotpb.GetSnapshotRequest, stream snapshotpb.ConfigSync_GetSnapshotServer) error {
		header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: "v1", TotalBytes: 100}}}
		return stream.Send(header)
	}}
	lis, _ := newBufServer(t, fake)
	client := dialClient(t, lis, "dp-1")

	_, _, _, err := client.Fetch(context.Background(), "")
	if err == nil {
		t.Fatal("Fetch: nil error, want length mismatch rejection")
	}
}

func TestClient_FetchRejectsOversizeHeader(t *testing.T) {
	fake := &fakeServer{getSnapshot: func(_ *snapshotpb.GetSnapshotRequest, stream snapshotpb.ConfigSync_GetSnapshotServer) error {
		header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: "v1", TotalBytes: maxSnapshotBytes + 1}}}
		return stream.Send(header)
	}}
	lis, _ := newBufServer(t, fake)
	client := dialClient(t, lis, "dp-1")

	_, _, _, err := client.Fetch(context.Background(), "")
	if err == nil {
		t.Fatal("Fetch: nil error, want oversize-header rejection")
	}
}

func TestClient_WatchAckRoundTrip(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger()))
	client := dialClient(t, lis, "dp-1")
	ctx := context.Background()

	version, err := client.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if version != "v1" {
		t.Fatalf("initial notice = %q, want v1 (stale Hello reconcile)", version)
	}

	if err := client.Ack(ctx, "v1"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	eventually(t, func() bool {
		conn := firstConn(hub)
		return conn != nil && conn.acked() == "v1"
	}, "control plane did not record the ack")

	hub.Broadcast("v2")
	version, err = client.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch after broadcast: %v", err)
	}
	if version != "v2" {
		t.Fatalf("broadcast notice = %q, want v2", version)
	}
}

func TestClient_WatchReconnectsOnStreamBreak(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	hub := NewHub(discardLogger(), nil)
	lis, gsrv := newBufServer(t, NewService(hub, src, discardLogger()))
	client := dialClient(t, lis, "dp-1")
	ctx := context.Background()

	if _, err := client.Watch(ctx); err != nil {
		t.Fatalf("initial Watch: %v", err)
	}

	gsrv.Stop()

	_, err := client.Watch(ctx)
	if err == nil {
		t.Fatal("Watch after stream break: nil error, want failure")
	}
	if !errors.Is(err, configsync.ErrTransportUnavailable) {
		t.Fatalf("Watch after stream break: err = %v, want configsync.ErrTransportUnavailable", err)
	}
	client.mu.Lock()
	streamReset := client.stream == nil
	client.mu.Unlock()
	if !streamReset {
		t.Fatal("stream was not reset after break; reconnect would reuse a dead stream")
	}
}

func TestStreamErr_ClassifiesRecoverableDisconnects(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		recoverable bool
	}{
		{name: "graceful goaway unavailable", err: status.Error(codes.Unavailable, "closing transport due to graceful_stop"), recoverable: true},
		{name: "canceled code", err: status.Error(codes.Canceled, "context canceled"), recoverable: true},
		{name: "stream eof", err: io.EOF, recoverable: true},
		{name: "context canceled", err: context.Canceled, recoverable: true},
		{name: "internal fault", err: status.Error(codes.Internal, "boom"), recoverable: false},
		{name: "plain error", err: errors.New("boom"), recoverable: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := streamErr("watch recv", tc.err)
			if errors.Is(got, configsync.ErrTransportUnavailable) != tc.recoverable {
				t.Fatalf("streamErr(%v) recoverable = %v, want %v", tc.err, !tc.recoverable, tc.recoverable)
			}
			if !errors.Is(got, tc.err) {
				t.Fatalf("streamErr must wrap the original error %v", tc.err)
			}
		})
	}
}

func firstConn(h *Hub) *connection {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.conns {
		return c
	}
	return nil
}
