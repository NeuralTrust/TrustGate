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
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding/gzip"
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

// SnapshotSource serves the encoded snapshot of a scope as segments whose
// concatenation is the snapshot, so a source can share segments across
// scopes without copying them per request.
type SnapshotSource interface {
	SnapshotPartsFor(scope string) (parts [][]byte, version string, ok bool)
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

	usage         UsageSource
	usageGateways GatewayResolver
	usageRetry    time.Duration
}

// NewService builds the ConfigSync server implementation. revocations may be
// nil, in which case open streams are never ended for a revoked token.
func NewService(hub *Hub, source SnapshotSource, logger *slog.Logger, revocations RevocationChecker, opts ...ServiceOption) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		hub:          hub,
		source:       source,
		revocations:  revocations,
		logger:       logger,
		helloTimeout: defaultHelloTimeout,
		usageRetry:   usageRetryInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
	layered := hello.GetAcceptsLayered() && s.layeredSource() != nil
	conn := s.hub.registerStream(identity, hello.GetInstanceId(), layered)
	defer s.hub.teardown(conn)
	// The interceptor admitted this token before the stream registered. A
	// revocation loaded in between is caught here: the refresher swaps the
	// snapshot before it walks the hub, so a stream that registered after
	// that walk sees the new snapshot now.
	if s.revoked(identity) {
		return errInvalidToken
	}

	if n, ok := s.currentNotice(scope, layered); ok && n.version != hello.GetLastAppliedVersion() {
		conn.enqueue(n)
	}

	var usageChanges <-chan struct{}
	var usageRetry <-chan time.Time
	var usage *usageStream
	if s.usage != nil && hello.GetAcceptsUsage() {
		changes, release := s.usage.Subscribe()
		defer release()
		usageChanges = changes
		retry := time.NewTicker(s.usageRetry)
		defer retry.Stop()
		usageRetry = retry.C
		usage = newUsageStream(s.usage, s.usageGateways, s.logger, scope, hello.GetAcceptsUsageChanges(), hello.GetAcceptsManagedLimit())
		if err := sendUsage(stream, usage.next(ctx)); err != nil {
			return err
		}
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
			if hb := msg.GetHeartbeat(); hb != nil {
				s.hub.markHeartbeat(conn, heartbeatFromProto(hb))
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
		case n := <-conn.notices:
			notice := &snapshotpb.ServerMessage{Msg: &snapshotpb.ServerMessage_Notice{Notice: &snapshotpb.VersionNotice{Version: n.version, Layered: n.layered}}}
			if err := stream.Send(notice); err != nil {
				return err
			}
			if usage != nil && usage.owed {
				if err := sendUsage(stream, usage.next(ctx)); err != nil {
					return err
				}
			}
		case <-usageChanges:
			if err := sendUsage(stream, usage.next(ctx)); err != nil {
				return err
			}
		case <-usageRetry:
			if usage.owed {
				if err := sendUsage(stream, usage.next(ctx)); err != nil {
					return err
				}
			}
		}
	}
}

func sendUsage(stream snapshotpb.ConfigSync_SyncServer, msgs []*snapshotpb.ServerMessage) error {
	for _, msg := range msgs {
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
	return nil
}

// GetSnapshot answers not_modified when the DP's applied_version matches current,
// otherwise streams a SnapshotHeader followed by fixed-size data chunks.
func (s *Service) GetSnapshot(req *snapshotpb.GetSnapshotRequest, stream snapshotpb.ConfigSync_GetSnapshotServer) error {
	scope := ScopeFromContext(stream.Context())
	identity, _ := IdentityFromContext(stream.Context())
	parts, version, ok := s.source.SnapshotPartsFor(scope)
	if !ok {
		return status.Error(codes.Unavailable, "no snapshot available yet")
	}
	if applied := req.GetAppliedVersion(); applied != "" && applied == version {
		header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: version, NotModified: true}}}
		return stream.Send(header)
	}
	s.compressSnapshot(stream.Context())
	var total int64
	for _, part := range parts {
		total += int64(len(part))
	}
	if total > maxSnapshotBytes {
		return status.Errorf(codes.ResourceExhausted, "snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	header := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Header{Header: &snapshotpb.SnapshotHeader{Version: version, TotalBytes: total}}}
	if err := stream.Send(header); err != nil {
		return err
	}
	for _, part := range parts {
		for offset := 0; offset < len(part); offset += snapshotChunkSize {
			// GetSnapshot streams are not registered in the hub, so a revocation
			// loaded mid-transfer is enforced here, before the next chunk.
			if s.revoked(identity) {
				return errInvalidToken
			}
			end := min(offset+snapshotChunkSize, len(part))
			chunk := &snapshotpb.SnapshotChunk{Payload: &snapshotpb.SnapshotChunk_Data{Data: part[offset:end]}}
			if err := stream.Send(chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

// compressSnapshot gzips the snapshot stream when the data plane advertises
// gzip. The data plane never compresses its own requests, so a data plane and
// a control plane of different versions keep working in either rollout order.
func (s *Service) compressSnapshot(ctx context.Context) {
	supported, err := grpc.ClientSupportedCompressors(ctx)
	if err != nil || !slices.Contains(supported, gzip.Name) {
		return
	}
	if err := grpc.SetSendCompressor(ctx, gzip.Name); err != nil {
		s.logger.Warn("snapshot stream sent uncompressed",
			slog.String("error", err.Error()))
	}
}
