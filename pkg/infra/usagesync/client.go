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

// Package usagesync is the control plane's client of Usage System's UsageSync
// stream: it keeps the usage store in step with the states Usage System
// decides.
package usagesync

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	usagev1 "github.com/NeuralTrust/TrustGate/pkg/infra/usagesync/proto/usage/v1"
)

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second

	// maxMessageBytes lifts gRPC's 4 MiB receive default: a snapshot lists
	// every exhausted tenant in one message, and one over the limit would
	// fail every connect.
	maxMessageBytes = 64 << 20
)

// StateSink receives the states read from the stream.
type StateSink interface {
	Apply(ctx context.Context, states []domain.TenantState) error
	ApplySnapshot(ctx context.Context, exhausted []domain.TenantState, asOfVersion int64) error
	Watermark() int64
}

// Client holds one UsageSync stream open and feeds a StateSink. Every
// (re)connection sends the sink's watermark and receives a full snapshot, so a
// change missed while disconnected is never lost.
type Client struct {
	conn   *grpc.ClientConn
	sink   StateSink
	logger *slog.Logger
}

// NewClient dials Usage System. The connection is lazy: nothing is sent until
// Run opens the stream.
func NewClient(cfg config.UsageConfig, sink StateSink, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	transport := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if cfg.GRPCInsecure {
		transport = insecure.NewCredentials()
	}
	opts := append([]grpc.DialOption{grpc.WithTransportCredentials(transport)}, streamDialOptions()...)
	if cfg.GRPCToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearer{token: cfg.GRPCToken, secure: !cfg.GRPCInsecure}))
	}
	conn, err := grpc.NewClient(cfg.GRPCAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("usagesync: dial %q: %w", cfg.GRPCAddr, err)
	}
	return newClient(conn, sink, logger), nil
}

func streamDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMessageBytes)),
	}
}

func newClient(conn *grpc.ClientConn, sink StateSink, logger *slog.Logger) *Client {
	return &Client{conn: conn, sink: sink, logger: logger}
}

// Run keeps the stream open until ctx ends, reconnecting with jittered
// exponential backoff. The wait resets after a stream that delivered data.
func (c *Client) Run(ctx context.Context) {
	wait := minBackoff
	for ctx.Err() == nil {
		received, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if received {
			wait = minBackoff
		}
		c.logger.WarnContext(ctx, "usagesync: stream ended, reconnecting", slog.Any("error", err), slog.Duration("retry_in", wait))
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(wait)):
		}
		wait = min(wait*2, maxBackoff)
	}
}

// Close releases the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) session(ctx context.Context) (bool, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := usagev1.NewUsageSyncServiceClient(c.conn).Sync(streamCtx)
	if err != nil {
		return false, fmt.Errorf("usagesync: open stream: %w", err)
	}
	hello := &usagev1.SyncRequest{Message: &usagev1.SyncRequest_Hello{Hello: &usagev1.Hello{LastVersion: c.sink.Watermark()}}}
	if err := stream.Send(hello); err != nil {
		return false, fmt.Errorf("usagesync: send hello: %w", err)
	}
	received := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return received, errors.New("usagesync: stream closed by Usage System")
			}
			return received, fmt.Errorf("usagesync: receive: %w", err)
		}
		version, err := c.apply(ctx, resp)
		if err != nil {
			return received, err
		}
		received = true
		ack := &usagev1.SyncRequest{Message: &usagev1.SyncRequest_Ack{Ack: &usagev1.Ack{Version: version}}}
		if err := stream.Send(ack); err != nil {
			return received, fmt.Errorf("usagesync: send ack: %w", err)
		}
	}
}

// apply hands one message to the sink and returns the version to ack. Acks
// only report progress to Usage System, so a change that cannot be read is
// acked at the watermark and the stream carries on.
func (c *Client) apply(ctx context.Context, resp *usagev1.SyncResponse) (int64, error) {
	switch msg := resp.GetMessage().(type) {
	case *usagev1.SyncResponse_Snapshot:
		snapshot := msg.Snapshot
		states := make([]domain.TenantState, 0, len(snapshot.GetExhausted()))
		for _, entry := range snapshot.GetExhausted() {
			if state, ok := c.listedState(ctx, entry); ok {
				states = append(states, state)
			}
		}
		if err := c.sink.ApplySnapshot(ctx, states, snapshot.GetAsOfVersion()); err != nil {
			return 0, fmt.Errorf("usagesync: apply snapshot: %w", err)
		}
		return snapshot.GetAsOfVersion(), nil
	case *usagev1.SyncResponse_Change:
		state, ok := c.changedState(ctx, msg.Change)
		if !ok {
			return c.sink.Watermark(), nil
		}
		if err := c.sink.Apply(ctx, []domain.TenantState{state}); err != nil {
			return 0, fmt.Errorf("usagesync: apply change: %w", err)
		}
		return state.Version, nil
	default:
		return c.sink.Watermark(), nil
	}
}

// listedState reads an entry of a snapshot's exhausted list. Being listed is
// what makes a tenant exhausted, whatever its status field says, so a snapshot
// never unblocks a tenant because one of its fields is unknown here.
func (c *Client) listedState(ctx context.Context, entry *usagev1.UsageState) (domain.TenantState, bool) {
	return c.newState(ctx, entry, domain.StatusExhausted)
}

// changedState reads a single change. A status this build does not know is
// dropped rather than read as healthy, so the tenant keeps its last state.
func (c *Client) changedState(ctx context.Context, entry *usagev1.UsageState) (domain.TenantState, bool) {
	switch entry.GetStatus() {
	case usagev1.UsageStatus_USAGE_STATUS_EXHAUSTED:
		return c.newState(ctx, entry, domain.StatusExhausted)
	case usagev1.UsageStatus_USAGE_STATUS_HEALTHY:
		return c.newState(ctx, entry, domain.StatusHealthy)
	default:
		c.logger.WarnContext(ctx, "usagesync: dropping a change with an unknown status",
			slog.String("tenant_id", entry.GetTenantId()), slog.String("status", entry.GetStatus().String()))
		return domain.TenantState{}, false
	}
}

func (c *Client) newState(ctx context.Context, entry *usagev1.UsageState, status domain.Status) (domain.TenantState, bool) {
	reason := domain.ReasonNone
	if status == domain.StatusExhausted {
		reason = c.reason(ctx, entry)
	}
	state, err := domain.NewTenantState(entry.GetTenantId(), status, reason, entry.GetVersion())
	if err != nil {
		c.logger.WarnContext(ctx, "usagesync: dropping invalid state", slog.String("tenant_id", entry.GetTenantId()), slog.Any("error", err))
		return domain.TenantState{}, false
	}
	return state, true
}

// reason maps an exhaustion reason. One this build does not know still
// blocks, as insufficient funds, because an exhausted tenant must not be
// served over a field it cannot read.
func (c *Client) reason(ctx context.Context, entry *usagev1.UsageState) domain.Reason {
	switch entry.GetReason() {
	case usagev1.ExhaustionReason_EXHAUSTION_REASON_FREE_LIMIT_REACHED:
		return domain.ReasonFreeLimitReached
	case usagev1.ExhaustionReason_EXHAUSTION_REASON_WALLET_EMPTY:
		return domain.ReasonWalletEmpty
	default:
		c.logger.WarnContext(ctx, "usagesync: unknown exhaustion reason, blocking as wallet_empty",
			slog.String("tenant_id", entry.GetTenantId()), slog.String("reason", entry.GetReason().String()))
		return domain.ReasonWalletEmpty
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) // #nosec G404 -- backoff jitter, not a secret
}

type bearer struct {
	token  string
	secure bool
}

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (b bearer) RequireTransportSecurity() bool { return b.secure }
