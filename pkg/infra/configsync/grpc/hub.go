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
	"log/slog"
	"sync"
)

// Hub is the registry of connected data-plane Sync streams. Broadcast fans a new
// version out to every connection through a latest-only, size-1 drop-oldest
// channel so a slow consumer never blocks the dispatcher and only the newest
// version is ever delivered.
type Hub struct {
	mu     sync.Mutex
	conns  map[*connection]struct{}
	logger *slog.Logger
}

// connection is one registered DP Sync stream. notices carries at most the
// latest pending version; lastAcked tracks the last version the DP reported for
// observability only.
type connection struct {
	instanceID string
	notices    chan string

	ackMu     sync.Mutex
	lastAcked string
}

// NewHub builds an empty Hub.
func NewHub(logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{conns: make(map[*connection]struct{}), logger: logger}
}

func (h *Hub) register(instanceID string) *connection {
	conn := &connection{instanceID: instanceID, notices: make(chan string, 1)}
	h.mu.Lock()
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
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
