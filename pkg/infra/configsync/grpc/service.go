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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxSnapshotBytes  = 256 << 20
	snapshotChunkSize = 1 << 20
	// defaultHelloTimeout bounds how long an admitted Sync stream may stay
	// open before it says Hello. A data plane sends Hello right after opening
	// the stream; until it does, the stream is not registered and a token
	// revocation could not reach it.
	defaultHelloTimeout = 10 * time.Second
)

type SnapshotSource interface {
	SnapshotFor(scope string) (raw []byte, version string, ok bool)
}

// Service implements the ConfigSync gRPC server: the bidi Sync control channel
// and the server-streaming GetSnapshot bulk transfer.
type Service struct {
	snapshotpb.UnimplementedConfigSyncServer
	hub          *Hub
	source       SnapshotSource
	revocations  RevocationChecker
	logger       *slog.Logger
	helloTimeout time.Duration
}

// NewService builds the ConfigSync server implementation. revocations may be
// nil, in which case open streams are never ended for a revoked token.
func NewService(hub *Hub, source SnapshotSource, logger *slog.Logger, revocations RevocationChecker) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{hub: hub, source: source, revocations: revocations, logger: logger, helloTimeout: defaultHelloTimeout}
}

func (s *Service) revoked(id configsyncrevocation.Identity) bool {
	return s.revocations != nil && s.revocations.Revoked(id)
}

type received struct {
	msg *snapshotpb.ClientMessage
	err error
}

// recvHello waits for the stream's first message for at most helloTimeout.
// Returning ends the RPC, which cancels the stream and unblocks the Recv.
func (s *Service) recvHello(stream snapshotpb.ConfigSync_SyncServer) (*snapshotpb.ClientMessage, error) {
	first := make(chan received, 1)
	go func() {
		msg, err := stream.Recv()
		first <- received{msg: msg, err: err}
	}()
	timer := time.NewTimer(s.helloTimeout)
	defer timer.Stop()
	select {
	case r := <-first:
		return r.msg, r.err
	case <-timer.C:
		return nil, status.Error(codes.DeadlineExceeded, "no Hello received on the Sync stream")
	case <-stream.Context().Done():
		return nil, stream.Context().Err()
	}
}

// Sync registers the data plane's stream, pushes an immediate notice when the
// DP's last-applied version is stale, then forwards broadcasts as VersionNotice
// messages while draining the DP's Acks.
func (s *Service) Sync(stream snapshotpb.ConfigSync_SyncServer) error {
	ctx := stream.Context()
	first, err := s.recvHello(stream)
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first Sync message must be Hello")
	}
	scope := ScopeFromContext(ctx)
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		identity = configsyncrevocation.Identity{Scope: scope}
	}
	conn := s.hub.register(identity, hello.GetInstanceId())
	defer s.hub.unregister(conn)
	defer s.hub.markDisconnected(conn)
	// The interceptor admitted this token before the stream registered. A
	// revocation loaded in between is caught here: the refresher swaps the
	// snapshot before it walks the hub, so a stream that registered after
	// that walk sees the new snapshot now.
	if s.revoked(identity) {
		return errInvalidToken
	}

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
		case <-conn.revoked:
			return errInvalidToken
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
	identity, _ := IdentityFromContext(stream.Context())
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
		// GetSnapshot streams are not registered in the hub, so a revocation
		// loaded mid-transfer is enforced here, before the next chunk.
		if s.revoked(identity) {
			return errInvalidToken
		}
		end := min(offset+snapshotChunkSize, len(raw))
		chunk := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Data{Data: raw[offset:end]}}
		if err := stream.Send(chunk); err != nil {
			return err
		}
	}
	return nil
}
