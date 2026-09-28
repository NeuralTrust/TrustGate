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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func startServer(t *testing.T, token string, src SnapshotSource) *Server {
	t.Helper()
	cfg := config.ConfigSyncConfig{
		GRPCListenAddr:       "127.0.0.1:0",
		Token:                token,
		GRPCKeepaliveTime:    30 * time.Second,
		GRPCKeepaliveTimeout: 10 * time.Second,
	}
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: config.ConfigSyncConfig{Token: token}}, discardLogger())
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	svc := NewService(NewHub(discardLogger(), nil), src, discardLogger())
	srv, err := NewServer(cfg, svc, nil, auth, discardLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return srv
}

func dialAddr(t *testing.T, addr, token string) snapshotpb.ConfigSyncClient {
	t.Helper()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearerPerRPCCredentials{token: token}))
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return snapshotpb.NewConfigSyncClient(conn)
}

func TestServer_AuthorizedGetSnapshot(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	srv := startServer(t, "tok", src)

	cli := dialAddr(t, srv.lis.Addr().String(), "tok")
	stream, err := cli.GetSnapshot(context.Background(), &snapshotpb.GetSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv header: %v", err)
	}
}

func TestServer_RejectsMissingToken(t *testing.T) {
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	srv := startServer(t, "tok", src)

	cli := dialAddr(t, srv.lis.Addr().String(), "")
	stream, err := cli.GetSnapshot(context.Background(), &snapshotpb.GetSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
}

func TestServer_ShutdownBoundsLongLivedStreams(t *testing.T) {
	cfg := config.ConfigSyncConfig{
		GRPCListenAddr:       "127.0.0.1:0",
		Token:                "tok",
		GRPCKeepaliveTime:    30 * time.Second,
		GRPCKeepaliveTimeout: 10 * time.Second,
	}
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger())
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	service := &blockingSyncServer{started: make(chan struct{})}
	srv, err := NewServer(cfg, service, nil, auth, discardLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Run() }()
	srv.gracefulStopTimeout = 20 * time.Millisecond
	client := dialAddr(t, srv.lis.Addr().String(), "tok")
	stream, err := client.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := stream.Send(&snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{InstanceId: "dp-1"}}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	select {
	case <-service.started:
	case <-time.After(time.Second):
		t.Fatal("sync stream did not start")
	}

	started := time.Now()
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("Shutdown took %v, want bounded stop", elapsed)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("active stream remained open after shutdown")
	}
}
