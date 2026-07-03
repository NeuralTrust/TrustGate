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
	auth := NewAuthInterceptor(&config.Config{ConfigSync: config.ConfigSyncConfig{Token: token}}, discardLogger())
	svc := NewService(NewHub(discardLogger()), src, discardLogger())
	srv, err := NewServer(cfg, svc, auth, discardLogger())
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
