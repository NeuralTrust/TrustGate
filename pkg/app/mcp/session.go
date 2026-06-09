package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

// Pin is the persisted upstream session state that lets any gateway replica
// resume the same upstream MCP session (no pod-local state, no LB stickiness).
type Pin struct {
	SessionID string `json:"session_id"`
	Protocol  string `json:"protocol"`
}

// SessionStore persists upstream session pins in a shared store (Redis).
type SessionStore interface {
	Get(ctx context.Context, key string) (*Pin, error) // nil when absent
	Set(ctx context.Context, key string, pin Pin) error
	Delete(ctx context.Context, key string) error
}

// NewPinnedDialer wraps the raw MCP client with shared-store session reuse:
// targets carrying a PinKey resume the stored upstream session; expired
// sessions (upstream 404) are re-initialized transparently and re-pinned.
func NewPinnedDialer(client *mcpclient.Client, store SessionStore, logger *slog.Logger) Dialer {
	return &pinnedDialer{client: client, store: store, logger: logger}
}

type pinnedDialer struct {
	client *mcpclient.Client
	store  SessionStore
	logger *slog.Logger
}

func (d *pinnedDialer) Connect(ctx context.Context, target mcpclient.Target) (Upstream, error) {
	if target.PinKey == "" {
		sess, err := d.client.Connect(ctx, target)
		if err != nil {
			return nil, err
		}
		return sess, nil
	}
	pin, err := d.store.Get(ctx, target.PinKey)
	if err != nil {
		d.logger.Warn("mcp session store read failed; connecting fresh", "error", err)
	}
	if pin != nil {
		sess := d.client.Resume(target, pin.SessionID, pin.Protocol)
		return &pinnedUpstream{dialer: d, target: target, session: sess}, nil
	}
	sess, err := d.connectAndPin(ctx, target)
	if err != nil {
		return nil, err
	}
	return &pinnedUpstream{dialer: d, target: target, session: sess}, nil
}

func (d *pinnedDialer) connectAndPin(ctx context.Context, target mcpclient.Target) (*mcpclient.Session, error) {
	sess, err := d.client.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	if sess.SessionID() != "" {
		if err := d.store.Set(ctx, target.PinKey, Pin{SessionID: sess.SessionID(), Protocol: sess.Protocol()}); err != nil {
			d.logger.Warn("mcp session store write failed", "error", err)
		}
	}
	return sess, nil
}

// pinnedUpstream retries operations once with a fresh session when the
// upstream reports the pinned session as expired.
type pinnedUpstream struct {
	dialer  *pinnedDialer
	target  mcpclient.Target
	session *mcpclient.Session
}

func (u *pinnedUpstream) ListTools(ctx context.Context) ([]mcpclient.Tool, error) {
	tools, err := u.session.ListTools(ctx)
	if u.refresh(ctx, err) {
		return u.session.ListTools(ctx)
	}
	return tools, err
}

func (u *pinnedUpstream) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	res, err := u.session.CallTool(ctx, name, arguments)
	if u.refresh(ctx, err) {
		return u.session.CallTool(ctx, name, arguments)
	}
	return res, err
}

func (u *pinnedUpstream) Close(context.Context) {
	// Pinned sessions stay alive for reuse; Redis TTL acts as the reaper.
}

// refresh replaces the expired session with a freshly initialized one and
// reports whether the failed operation should be retried.
func (u *pinnedUpstream) refresh(ctx context.Context, err error) bool {
	if err == nil || !errors.Is(err, mcpclient.ErrSessionExpired) {
		return false
	}
	if delErr := u.dialer.store.Delete(ctx, u.target.PinKey); delErr != nil {
		u.dialer.logger.Warn("mcp session store delete failed", "error", delErr)
	}
	sess, connErr := u.dialer.connectAndPin(ctx, u.target)
	if connErr != nil {
		return false
	}
	u.session = sess
	return true
}
