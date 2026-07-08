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
	"errors"
	"io"
	"log/slog"

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxSnapshotBytes  = 256 << 20
	snapshotChunkSize = 1 << 20
)

type SnapshotSource interface {
	SnapshotFor(scope string) (raw []byte, version string, ok bool)
}

// Service implements the ConfigSync gRPC server: the bidi Sync control channel
// and the server-streaming GetSnapshot bulk transfer.
type Service struct {
	snapshotpb.UnimplementedConfigSyncServer
	hub    *Hub
	source SnapshotSource
	logger *slog.Logger
}

// NewService builds the ConfigSync server implementation.
func NewService(hub *Hub, source SnapshotSource, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{hub: hub, source: source, logger: logger}
}

// Sync registers the data plane's stream, pushes an immediate notice when the
// DP's last-applied version is stale, then forwards broadcasts as VersionNotice
// messages while draining the DP's Acks.
func (s *Service) Sync(stream snapshotpb.ConfigSync_SyncServer) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first Sync message must be Hello")
	}
	scope := ScopeFromContext(ctx)
	conn := s.hub.register(scope, hello.GetInstanceId())
	defer s.hub.unregister(conn)
	defer s.hub.markDisconnected(conn)

	if _, version, ok := s.source.SnapshotFor(scope); ok && version != hello.GetLastAppliedVersion() {
		conn.enqueue(version)
	}

	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if ack := msg.GetAck(); ack != nil {
				s.hub.markAck(conn, ack.GetAppliedVersion())
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case version := <-conn.notices:
			notice := &snapshotpb.ServerMessage{Msg: &snapshotpb.ServerMessage_Notice{Notice: &snapshotpb.VersionNotice{Version: version}}}
			if err := stream.Send(notice); err != nil {
				return err
			}
		}
	}
}

// GetSnapshot answers not_modified when the DP's applied_version matches current,
// otherwise streams a SnapshotHeader followed by fixed-size data chunks.
func (s *Service) GetSnapshot(req *snapshotpb.GetSnapshotRequest, stream snapshotpb.ConfigSync_GetSnapshotServer) error {
	scope := ScopeFromContext(stream.Context())
	raw, version, ok := s.source.SnapshotFor(scope)
	if !ok {
		return status.Error(codes.Unavailable, "no snapshot available yet")
	}
	if applied := req.GetAppliedVersion(); applied != "" && applied == version {
		header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: version, NotModified: true}}}
		return stream.Send(header)
	}
	if int64(len(raw)) > maxSnapshotBytes {
		return status.Errorf(codes.ResourceExhausted, "snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: version, TotalBytes: int64(len(raw))}}}
	if err := stream.Send(header); err != nil {
		return err
	}
	for offset := 0; offset < len(raw); offset += snapshotChunkSize {
		end := min(offset+snapshotChunkSize, len(raw))
		chunk := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Data{Data: raw[offset:end]}}
		if err := stream.Send(chunk); err != nil {
			return err
		}
	}
	return nil
}
