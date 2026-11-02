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
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
)

// storeWriteTimeout bounds a best-effort connection-store write so a stalled
// admin Postgres can never hang a Sync stream or its teardown.
const storeWriteTimeout = 5 * time.Second

// Hub is the registry of connected data-plane Sync streams. Broadcast fans a new
// version out to every connection through a latest-only, size-1 drop-oldest
// channel so a slow consumer never blocks the dispatcher and only the newest
// version is ever delivered. When a ConnectionStore is present the Hub also
// records each stream's lifecycle best-effort for the admin read API.
type Hub struct {
	mu     sync.Mutex
	conns  map[*connection]struct{}
	logger *slog.Logger
	store  ConnectionStore
	// presenceMu orders a presence refresh against teardowns: a refresh holds
	// it exclusively from the snapshot of held streams until its write lands,
	// and a teardown holds it shared while it marks the stream disconnected,
	// so a refresh can never re-mark a stream that has just closed.
	presenceMu sync.RWMutex
}

// connection is one registered DP Sync stream. notices carries at most the
// latest pending version; lastAcked tracks the last version the DP reported for
// observability only. scope is the verified, opaque tenant scope from the JWT.
// identity is the verified token the stream opened with; revoked is closed
// once that token is revoked, which ends the stream.
type connection struct {
	scope      string
	identity   configsyncrevocation.Identity
	instanceID string
	notices    chan string
	revoked    chan struct{}
	revokeOnce sync.Once

	ackMu     sync.Mutex
	lastAcked string

	// writeMu serialises this stream's store writes with its teardown; once
	// closed is set, acks and heartbeats still in flight are not persisted.
	writeMu sync.Mutex
	closed  bool
}

// NewHub builds an empty Hub. store may be nil, in which case connection
// lifecycle is not persisted (in-memory-only self-host).
func NewHub(logger *slog.Logger, store ConnectionStore) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{conns: make(map[*connection]struct{}), logger: logger, store: store}
}

func (h *Hub) register(id configsyncrevocation.Identity, instanceID string) *connection {
	conn := &connection{
		scope:      id.Scope,
		identity:   id,
		instanceID: instanceID,
		notices:    make(chan string, 1),
		revoked:    make(chan struct{}),
	}
	h.mu.Lock()
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
	h.markConnected(conn)
	return conn
}

func (h *Hub) unregister(conn *connection) {
	h.mu.Lock()
	delete(h.conns, conn)
	h.mu.Unlock()
}

// teardown unregisters conn and then records it as disconnected, as the last
// store write for this stream: acks and heartbeats the receive goroutine still
// delivers are dropped, and no presence refresh can follow. When this replica
// already holds a newer stream for the same data plane, the row is left to
// that stream.
func (h *Hub) teardown(conn *connection) {
	h.mu.Lock()
	delete(h.conns, conn)
	superseded := false
	for other := range h.conns {
		if other.scope == conn.scope && other.instanceID == conn.instanceID {
			superseded = true
			break
		}
	}
	h.mu.Unlock()
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	conn.closed = true
	if superseded {
		return
	}
	h.presenceMu.RLock()
	defer h.presenceMu.RUnlock()
	h.markDisconnected(conn)
}

// Broadcast delivers version to every connected data plane, coalescing to the
// newest version per connection. It never blocks.
func (h *Hub) Broadcast(version string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.conns {
		conn.enqueue(version)
	}
}

// BroadcastScope delivers version only to connections registered under scope,
// coalescing to the newest version per connection and never blocking. Multiple
// pods sharing one instance scope all receive the notice; other scopes are left
// undisturbed. An empty scope targets the in-cluster shared/composite data
// planes that serve the global snapshot.
func (h *Hub) BroadcastScope(scope, version string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.conns {
		if conn.scope == scope {
			conn.enqueue(version)
		}
	}
}

// CloseRevoked ends every registered Sync stream whose verified token satisfies
// isRevoked and returns how many this call closed. GetSnapshot transfers are
// not registered; they check revocation before each chunk instead. The check keys on the token
// the stream authenticated with, never on the instance id the DP announced.
func (h *Hub) CloseRevoked(isRevoked func(configsyncrevocation.Identity) bool) int {
	h.mu.Lock()
	conns := make([]*connection, 0, len(h.conns))
	for conn := range h.conns {
		conns = append(conns, conn)
	}
	h.mu.Unlock()
	closed := 0
	for _, conn := range conns {
		if isRevoked(conn.identity) && conn.revoke() {
			closed++
		}
	}
	return closed
}

// ConnectionCount reports the number of registered data-plane streams.
func (h *Hub) ConnectionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

func (c *connection) enqueue(version string) {
	select {
	case c.notices <- version:
		return
	default:
	}
	select {
	case <-c.notices:
	default:
	}
	select {
	case c.notices <- version:
	default:
	}
}

func (c *connection) revoke() bool {
	revoked := false
	c.revokeOnce.Do(func() {
		close(c.revoked)
		revoked = true
	})
	return revoked
}

func (c *connection) recordAck(version string) {
	c.ackMu.Lock()
	c.lastAcked = version
	c.ackMu.Unlock()
}

func (c *connection) acked() string {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.lastAcked
}

// markConnected records the stream as connected. Best-effort: errors are logged
// and swallowed so a store failure never blocks the data plane.
func (h *Hub) markConnected(conn *connection) {
	if h.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()
	if err := h.store.MarkConnected(ctx, conn.scope, conn.instanceID); err != nil {
		h.logStoreErr("mark connected", conn, err)
	}
}

// markAck records the DP's applied version for observability and persists it
// best-effort.
func (h *Hub) markAck(conn *connection, appliedVersion string) {
	conn.recordAck(appliedVersion)
	if h.store == nil {
		return
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if conn.closed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()
	if err := h.store.MarkAck(ctx, conn.scope, conn.instanceID, appliedVersion); err != nil {
		h.logStoreErr("mark ack", conn, err)
	}
}

// markDisconnected records the stream as disconnected. It runs from the stream's
// teardown after the request context is already cancelled, so it uses its own
// bounded context rather than the dead stream context.
func (h *Hub) markDisconnected(conn *connection) {
	if h.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()
	if err := h.store.MarkDisconnected(ctx, conn.scope, conn.instanceID); err != nil {
		h.logStoreErr("mark disconnected", conn, err)
	}
}

// markHeartbeat persists what the data plane reported, best-effort.
func (h *Hub) markHeartbeat(conn *connection, hb dataplane.Heartbeat) {
	if h.store == nil {
		return
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if conn.closed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()
	if err := h.store.MarkHeartbeat(ctx, conn.scope, conn.instanceID, hb); err != nil {
		h.logStoreErr("mark heartbeat", conn, err)
	}
}

// RunPresence marks every stream this replica holds connected and refreshes
// its last_seen, each interval, until ctx is done. A data plane that predates
// heartbeats still shows as live while its stream is open, even when a stale
// teardown on another replica marked it disconnected, and the streams of a
// replica that dies stop being refreshed and age out.
func (h *Hub) RunPresence(ctx context.Context, interval time.Duration) {
	if h.store == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.refreshPresence(ctx)
		}
	}
}

func (h *Hub) refreshPresence(ctx context.Context) {
	h.presenceMu.Lock()
	defer h.presenceMu.Unlock()
	h.mu.Lock()
	keys := make([]dataplane.StreamKey, 0, len(h.conns))
	for conn := range h.conns {
		keys = append(keys, dataplane.StreamKey{Scope: conn.scope, InstanceID: conn.instanceID})
	}
	h.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, storeWriteTimeout)
	defer cancel()
	if err := h.store.TouchConnected(writeCtx, keys); err != nil && ctx.Err() == nil {
		h.logger.Warn("config-sync connection store write failed",
			slog.String("component", "configsync-hub"),
			slog.String("op", "refresh presence"),
			slog.Int("streams", len(keys)),
			slog.String("error", err.Error()))
	}
}

func (h *Hub) logStoreErr(op string, conn *connection, err error) {
	h.logger.Warn("config-sync connection store write failed",
		slog.String("component", "configsync-hub"),
		slog.String("op", op),
		slog.String("scope", conn.scope),
		slog.String("instance_id", conn.instanceID),
		slog.String("error", err.Error()))
}
