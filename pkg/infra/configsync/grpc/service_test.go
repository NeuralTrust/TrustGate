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
	"net"
	"testing"
	"time"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestService_SyncUnregistersOnClose(t *testing.T) {
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, &fakeSource{}, discardLogger()))
	client := dialClient(t, lis, "dp-1")

	go func() { _, _ = client.Watch(context.Background()) }()

	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	// The Sync stream is owned by the client lifecycle, not the Watch caller's
	// context, so tearing it down is done via Close.
	_ = client.Close()
	eventually(t, func() bool { return hub.ConnectionCount() == 0 }, "stream not unregistered on close")
}

func TestService_SyncNoInitialNoticeWhenUpToDate(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	hub := NewHub(discardLogger(), nil)
	lis, _ := newBufServer(t, NewService(hub, src, discardLogger()))
	client := dialClient(t, lis, "dp-1")
	client.mu.Lock()
	client.lastApplied = "v1"
	client.mu.Unlock()

	got := make(chan string, 1)
	go func() {
		if v, err := client.Watch(context.Background()); err == nil {
			got <- v
		}
	}()

	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	select {
	case v := <-got:
		t.Fatalf("received unexpected notice %q for an up-to-date data plane", v)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestService_SyncRejectsNonHelloFirstMessage(t *testing.T) {
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), &fakeSource{}, discardLogger()))
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	stream, err := snapshotpb.NewConfigSyncClient(conn).Sync(context.Background())
	if err != nil {
		t.Fatalf("open sync: %v", err)
	}
	ack := &snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Ack{Ack: &snapshotpb.Ack{AppliedVersion: "v1"}}}
	if err := stream.Send(ack); err != nil {
		t.Fatalf("send ack: %v", err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("Recv: nil error, want InvalidArgument for non-Hello first message")
	}
}

func TestService_GetSnapshotStreamsHeaderThenChunks(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("hello-world"), "v1")
	lis, _ := newBufServer(t, NewService(NewHub(discardLogger(), nil), src, discardLogger()))
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	stream, err := snapshotpb.NewConfigSyncClient(conn).GetSnapshot(context.Background(), &snapshotpb.GetSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv header: %v", err)
	}
	header := first.GetHeader()
	if header == nil {
		t.Fatal("first message is not a header")
	}
	if header.GetNotModified() {
		t.Fatal("not_modified = true, want false for a stale applied version")
	}
	if header.GetVersion() != "v1" || header.GetTotalBytes() != int64(len("hello-world")) {
		t.Fatalf("header = %+v, want version v1 / total %d", header, len("hello-world"))
	}
}
