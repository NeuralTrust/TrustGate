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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/gofiber/fiber/v2"
)

// maxSurfaceMemoryEntries caps what the handler remembers about callers it has
// answered. Past it the oldest key is dropped, which costs that caller one
// missed announcement, not correctness: the next change announces itself.
const maxSurfaceMemoryEntries = 4096

// surfaceMemory remembers the surface each caller was last answered with.
//
// tools/list_changed has one other route out — the GET notification stream —
// and it only exists while the client holds that GET open. A client that does
// not, or whose stream was down when the change landed, keeps serving a tool
// list from its handshake until someone presses refresh by hand. Comparing the
// surface against what the caller last saw lets the next POST carry the news,
// which needs no stream at all.
type surfaceMemory struct {
	mu    sync.Mutex
	seen  map[string]string
	order []string
}

func newSurfaceMemory() *surfaceMemory {
	return &surfaceMemory{seen: make(map[string]string)}
}

// moved records the snapshot and reports whether it differs from the one this
// caller was last answered with. The first sighting is never a change: there is
// nothing the client could have missed before we had seen anything.
func (m *surfaceMemory) moved(key, snapshot string) bool {
	if m == nil || key == "" || snapshot == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, known := m.seen[key]
	if !known {
		if len(m.order) >= maxSurfaceMemoryEntries {
			delete(m.seen, m.order[0])
			m.order = m.order[1:]
		}
		m.order = append(m.order, key)
	}
	m.seen[key] = snapshot
	return known && previous != snapshot
}

// clientAcceptsEventStream reports whether this POST may be answered with a
// stream. The streamable HTTP transport has the client advertise both content
// types it can read, so this is the client's own word that it can — a client
// that only asked for JSON keeps getting JSON.
func clientAcceptsEventStream(c *fiber.Ctx) bool {
	return strings.Contains(c.Get(fiber.HeaderAccept), eventStreamContentType)
}

// surfaceMoved reports whether the caller's tool surface has changed since the
// last request we answered them.
//
// The watch snapshot is cached briefly, so a change made by the very call being
// answered can land one request late. That is the difference between a client
// that refreshes by itself on the next thing the user says and one that needs a
// person to find the menu item.
func (h *Handler) surfaceMoved(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) bool {
	if h.surface == nil || h.memory == nil || !clientAcceptsEventStream(c) {
		return false
	}
	if rc == nil || rc.Consumer == nil {
		return false
	}
	principal := identity.PrincipalFromContext(c.UserContext())
	if principal == nil || principal.Subject == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
	defer cancel()
	snapshot := h.surface.WatchSnapshot(ctx, rc, principal)
	key := rc.Consumer.GatewayID.String() + "|" + rc.Consumer.ID.String() + "|" + principal.Subject
	return h.memory.moved(key, snapshot)
}

// surfaceVersion is the value a client keys its cached tool list on, in
// server/discover's serverInfo and in initialize's.
//
// It has to move whenever the caller's tools do. SurfaceFingerprint reads the
// consumer's own record — bound registries and toolkit — which describes a
// custom MCP consumer exactly and the MCP Store not at all: the Store's
// consumer is synthetic, carries no registries, and resolves its servers per
// caller at dispatch. So on the Store that fingerprint was the same string for
// everyone, forever, and a client that trusts it (Claude Code probes with
// server/discover before anything else) had no reason to ever re-list. The
// watch snapshot is the same surface the notification stream watches, so the
// version now moves with an install, a connect, or a revoked grant.
func (h *Handler) surfaceVersion(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) string {
	principal := identity.PrincipalFromContext(c.UserContext())
	if h.surface == nil || principal == nil {
		return appmcp.SurfaceFingerprint(rc, nil)
	}
	ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
	defer cancel()
	snapshot := h.surface.WatchSnapshot(ctx, rc, principal)
	if snapshot == "" {
		// A caller the watcher cannot read — no principal it recognises — still
		// gets a version off the record. Asking it a second question here would
		// only add a credential read to every handshake.
		return appmcp.SurfaceFingerprint(rc, nil)
	}
	return appmcp.FingerprintSnapshot(snapshot)
}

// changesTheSurface reports whether this request is one that, having succeeded,
// has certainly changed what the caller can reach.
//
// surfaceMoved reads a snapshot cached for a few seconds, so the call that made
// the change is the one likeliest to be answered from a snapshot taken before
// it — the announcement would then wait for the next request. On an install or
// an uninstall there is nothing to detect: the tools changed because the caller
// just asked for them to.
func changesTheSurface(method string, params json.RawMessage) bool {
	if method != "tools/call" {
		return false
	}
	var call struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return false
	}
	return call.Name == appmcp.StoreInstallToolName || call.Name == appmcp.StoreUninstallToolName
}

// writeRPCBody sends one JSON-RPC response, as a lone JSON document or — when
// the caller's tools have changed under them — as a short stream carrying the
// response and then notifications/tools/list_changed.
func writeRPCBody(c *fiber.Ctx, body any, listChanged bool) error {
	if !listChanged {
		return writeJSON(c, body)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return writeJSON(c, body)
	}
	c.Set(fiber.HeaderContentType, eventStreamContentType)
	c.Set(fiber.HeaderCacheControl, "no-cache, no-store")
	// A proxy that buffered this would deliver the notification only once the
	// response was complete, which for a single-shot stream is never.
	c.Set("X-Accel-Buffering", "no")
	return c.Status(fiber.StatusOK).SendString(
		"event: message\ndata: " + string(payload) + "\n\n" + toolsListChangedFrame,
	)
}
