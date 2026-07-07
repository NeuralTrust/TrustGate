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
	"io"
	"log/slog"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// Client is the data-plane end of the config-sync transport. It implements
// configsync.ConfigFetcher (Fetch via GetSnapshot) and configsync.StreamTransport
// (Watch/Ack via the long-lived Sync stream), reconnecting the Sync stream on
// break.
type Client struct {
	conn       *grpc.ClientConn
	cli        snapshotpb.ConfigSyncClient
	instanceID string
	endpoint   string
	logger     *slog.Logger

	// streamCtx owns the lifecycle of the long-lived Sync stream so it is not
	// bound to any single Watch/Ack caller's context; cancelling it (via Close)
	// tears the stream down for shutdown.
	streamCtx    context.Context
	streamCancel context.CancelFunc

	mu          sync.Mutex
	stream      snapshotpb.ConfigSync_SyncClient
	lastApplied string
}

// NewClient dials the control plane with TLS (or dev-insecure), per-RPC bearer
// credentials, and keepalive tuning.
func NewClient(cfg config.ConfigSyncConfig, logger *slog.Logger) (*Client, error) {
	creds, err := clientTransportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithPerRPCCredentials(newBearerPerRPCCredentials(cfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                cfg.GRPCKeepaliveTime,
			Timeout:             cfg.GRPCKeepaliveTimeout,
			PermitWithoutStream: true,
		}),
	}
	conn, err := grpc.NewClient(cfg.GRPCEndpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("configsync: dial %q: %w", cfg.GRPCEndpoint, err)
	}
	c := newClient(conn, cfg.InstanceID, logger)
	c.endpoint = cfg.GRPCEndpoint
	return c, nil
}

// Endpoint returns the control-plane gRPC address the client dials.
func (c *Client) Endpoint() string {
	return c.endpoint
}

func newClient(conn *grpc.ClientConn, instanceID string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	streamCtx, streamCancel := context.WithCancel(context.Background())
	return &Client{
		conn:         conn,
		cli:          snapshotpb.NewConfigSyncClient(conn),
		instanceID:   instanceID,
		logger:       logger,
		streamCtx:    streamCtx,
		streamCancel: streamCancel,
	}
}

// Close cancels the Sync stream context and tears down the underlying
// connection, unblocking any in-flight stream receive.
func (c *Client) Close() error {
	c.streamCancel()
	return c.conn.Close()
}

// Fetch pulls the current snapshot via GetSnapshot, short-circuiting on
// not_modified and verifying the reassembled body length against the header.
func (c *Client) Fetch(ctx context.Context, etag string) ([]byte, string, bool, error) {
	stream, err := c.cli.GetSnapshot(ctx, &snapshotpb.GetSnapshotRequest{AppliedVersion: etag, InstanceId: c.instanceID})
	if err != nil {
		return nil, "", false, fmt.Errorf("configsync: get snapshot: %w", err)
	}
	first, err := stream.Recv()
	if err != nil {
		return nil, "", false, fmt.Errorf("configsync: read snapshot header: %w", err)
	}
	header := first.GetHeader()
	if header == nil {
		return nil, "", false, fmt.Errorf("configsync: first snapshot chunk is not a header")
	}
	if header.GetNotModified() {
		return nil, "", true, nil
	}
	total := header.GetTotalBytes()
	if total < 0 || total > maxSnapshotBytes {
		return nil, "", false, fmt.Errorf("configsync: snapshot header size %d out of bounds", total)
	}
	buf := make([]byte, 0, total)
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", false, fmt.Errorf("configsync: read snapshot chunk: %w", err)
		}
		buf = append(buf, msg.GetData()...)
		if int64(len(buf)) > maxSnapshotBytes {
			return nil, "", false, fmt.Errorf("configsync: snapshot body exceeds %d bytes", int64(maxSnapshotBytes))
		}
	}
	if int64(len(buf)) != total {
		return nil, "", false, fmt.Errorf("configsync: snapshot body length %d != header total %d", len(buf), total)
	}
	return buf, header.GetVersion(), false, nil
}

// Watch blocks for the next VersionNotice on the Sync stream, reopening the
// stream (and re-sending Hello) when it is not yet established or has broken.
func (c *Client) Watch(_ context.Context) (string, error) {
	stream, err := c.ensureStream()
	if err != nil {
		return "", err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			c.resetStream()
			return "", streamErr("watch recv", err)
		}
		if notice := msg.GetNotice(); notice != nil {
			return notice.GetVersion(), nil
		}
	}
}

// Ack reports the applied version to the control plane over the Sync stream.
func (c *Client) Ack(_ context.Context, appliedVersion string) error {
	stream, err := c.ensureStream()
	if err != nil {
		return err
	}
	ack := &snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Ack{Ack: &snapshotpb.Ack{AppliedVersion: appliedVersion}}}
	if err := stream.Send(ack); err != nil {
		c.resetStream()
		return fmt.Errorf("configsync: ack send: %w", err)
	}
	c.mu.Lock()
	c.lastApplied = appliedVersion
	c.mu.Unlock()
	return nil
}

func (c *Client) ensureStream() (snapshotpb.ConfigSync_SyncClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream, nil
	}
	stream, err := c.cli.Sync(c.streamCtx)
	if err != nil {
		return nil, streamErr("open sync stream", err)
	}
	hello := &snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{
		InstanceId:         c.instanceID,
		LastAppliedVersion: c.lastApplied,
	}}}
	if err := stream.Send(hello); err != nil {
		return nil, streamErr("send hello", err)
	}
	c.stream = stream
	return stream, nil
}

func (c *Client) resetStream() {
	c.mu.Lock()
	c.stream = nil
	c.mu.Unlock()
}

// streamErr wraps a broken Sync-stream error under op, tagging it with
// configsync.ErrTransportUnavailable when the disconnect is expected and
// self-healing so the worker logs a reconnect at WARN instead of ERROR.
func streamErr(op string, err error) error {
	if recoverableStreamErr(err) {
		return fmt.Errorf("configsync: %s: %w: %w", op, configsync.ErrTransportUnavailable, err)
	}
	return fmt.Errorf("configsync: %s: %w", op, err)
}

// recoverableStreamErr reports whether a Sync-stream error is an expected,
// self-healing disconnect: a control-plane restart/rollout (graceful GOAWAY
// surfaces as codes.Unavailable), a cancelled stream, or a clean EOF.
func recoverableStreamErr(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.Canceled:
		return true
	default:
		return false
	}
}
