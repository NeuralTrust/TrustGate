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
}

// connection is one registered DP Sync stream. notices carries at most the
// latest pending version; lastAcked tracks the last version the DP reported for
// observability only. scope is the verified, opaque tenant scope from the JWT.
type connection struct {
	scope      string
	instanceID string
	notices    chan string

	ackMu     sync.Mutex
	lastAcked string
}

// NewHub builds an empty Hub. store may be nil, in which case connection
// lifecycle is not persisted (in-memory-only self-host).
func NewHub(logger *slog.Logger, store ConnectionStore) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{conns: make(map[*connection]struct{}), logger: logger, store: store}
}

func (h *Hub) register(scope, instanceID string) *connection {
	conn := &connection{scope: scope, instanceID: instanceID, notices: make(chan string, 1)}
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

func (h *Hub) logStoreErr(op string, conn *connection, err error) {
	h.logger.Warn("config-sync connection store write failed",
		slog.String("component", "configsync-hub"),
		slog.String("op", op),
		slog.String("scope", conn.scope),
		slog.String("instance_id", conn.instanceID),
		slog.String("error", err.Error()))
}
