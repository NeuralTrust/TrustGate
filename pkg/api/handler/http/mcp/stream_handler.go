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
	"bufio"
	"context"
	"sort"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/gofiber/fiber/v2"
)

const eventStreamContentType = "text/event-stream"

// toolsListChangedFrame is the server-to-client notification an MCP client
// answers by re-issuing tools/list.
const toolsListChangedFrame = "event: message\n" +
	`data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` + "\n\n"

// streamKeepAliveFrame is an SSE comment: it carries no message but proves the
// connection is still writable, which is how a closed client is detected on an
// otherwise idle stream.
const streamKeepAliveFrame = ": keepalive\n\n"

// defaultStreamTimings closes the stream well before the server's write
// deadline (SERVER_WRITE_TIMEOUT, 60s by default) so the client sees a clean end
// and reopens, rather than having a write killed under it. A shorter deadline
// than this is still safe: the failed flush ends the loop the same way.
var defaultStreamTimings = streamTimings{
	poll:      5 * time.Second,
	keepAlive: 20 * time.Second,
	lifetime:  45 * time.Second,
}

type streamTimings struct {
	poll      time.Duration
	keepAlive time.Duration
	lifetime  time.Duration
}

// WantsEventStream reports whether a GET is the streamable-HTTP notification
// stream rather than a stray browser or probe request.
func WantsEventStream(c *fiber.Ctx) bool {
	return strings.Contains(c.Get(fiber.HeaderAccept), eventStreamContentType)
}

// Stream serves the server-to-client SSE stream of the streamable HTTP
// transport. Federation skips upstreams pending consent, so a user who connects
// an account on the connect page gains tools without the MCP session knowing:
// the client cached its tool list at handshake time and nothing invalidates it.
// This stream watches the caller's stored credentials and pushes
// notifications/tools/list_changed when they change, which is the only signal
// that makes a client re-list without reconnecting.
func (h *Handler) Stream(c *fiber.Ctx) error {
	skipMetrics(c)
	if !WantsEventStream(c) {
		return h.MethodNotAllowed(c)
	}
	rc, err := resolveMCPConsumer(c)
	if err != nil {
		return err
	}
	rc, err = h.scopeByRoles(c, rc)
	if err != nil {
		return err
	}
	principal := identity.PrincipalFromContext(c.UserContext())
	// The resolved gateway rides the request context; the poll runs on its own
	// context after the handler returns, so carry it over for the live Store
	// mode decision (own policy → groups → gateway default).
	gw, _ := appgateway.FromContext(c.UserContext())
	snapshot := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Watch the caller's connected accounts, their Store installations AND the
		// surface the Store actually exposes to them, so connecting an account,
		// installing a server, and an admin revoking a grant or tightening their
		// level each push a refresh. Without the surface, a revoked server would
		// stay in the client's cached tool list (its calls failing) until it
		// reconnected: the install row is unchanged, only the grant is.
		// connectionWatchSnapshot (not connectionSnapshot) is used deliberately: it
		// does not filter by the frozen consumer's forwarded providers, so a server
		// installed after the stream opened still pushes a refresh when connected.
		parts := h.connectionWatchSnapshot(ctx, rc, principal)
		parts = append(parts, h.installSnapshot(ctx, rc, principal)...)
		parts = append(parts, h.surfaceSnapshot(ctx, rc, principal, gw)...)
		return strings.Join(parts, "|")
	}

	c.Set(fiber.HeaderContentType, eventStreamContentType)
	c.Set(fiber.HeaderCacheControl, "no-cache, no-store")
	c.Set(fiber.HeaderConnection, "keep-alive")
	// Proxies that buffer a response would hold every notification until the
	// stream closes, which defeats the point of pushing one.
	c.Set("X-Accel-Buffering", "no")
	c.Status(fiber.StatusOK)
	timings := h.timings
	if timings.poll <= 0 {
		timings = defaultStreamTimings
	}
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		streamToolChanges(w, snapshot, timings)
	})
	return nil
}

// surfaceSnapshot fingerprints the registries the Store exposes to the caller
// right now — the same scoping tools/list applies (installs re-checked against
// the live grants and the caller's access level). It is what changes when an
// admin revokes a grant, sets the user or a group to Selected/None, or removes
// an instance: the install rows stay, the surface shrinks, and the client must
// re-list. Empty when the Store scoper is not wired or the consumer is not the
// Store; a transient scoper error reads as "no change" rather than a refresh.
func (h *Handler) surfaceSnapshot(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
	gw *gatewaydomain.Gateway,
) []string {
	if h.gateway == nil || h.gateway.storeScoper == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil
	}
	scopeCtx := identity.WithPrincipal(ctx, principal)
	if gw != nil {
		scopeCtx = appgateway.WithGateway(scopeCtx, gw)
	}
	scoped, err := h.gateway.storeScoper.Scope(scopeCtx, rc)
	if err != nil || scoped == nil {
		return nil
	}
	parts := make([]string, 0, len(scoped.Registries))
	for _, reg := range scoped.Registries {
		if reg == nil {
			continue
		}
		parts = append(parts, "sf:"+reg.ID.String()+"/"+reg.Name)
	}
	sort.Strings(parts)
	return parts
}

// streamToolChanges holds the stream open, pushing a notification whenever the
// watched surface changes. It returns when the client goes away (a write to a
// closed connection fails) or the lifetime cap expires, at which point the
// client is free to open a new stream.
func streamToolChanges(w *bufio.Writer, snapshot func() string, timings streamTimings) {
	previous := snapshot()
	if !flushFrame(w, streamKeepAliveFrame) {
		return
	}
	poll := time.NewTicker(timings.poll)
	defer poll.Stop()
	keepAlive := time.NewTicker(timings.keepAlive)
	defer keepAlive.Stop()
	deadline := time.After(timings.lifetime)
	for {
		select {
		case <-deadline:
			return
		case <-keepAlive.C:
			if !flushFrame(w, streamKeepAliveFrame) {
				return
			}
		case <-poll.C:
			current := snapshot()
			if current == previous {
				continue
			}
			previous = current
			if !flushFrame(w, toolsListChangedFrame) {
				return
			}
		}
	}
}

func flushFrame(w *bufio.Writer, frame string) bool {
	if _, err := w.WriteString(frame); err != nil {
		return false
	}
	return w.Flush() == nil
}

// StreamRoute returns the handler chain for the notification stream: a GET that
// is not asking for the event stream keeps answering 405 without ever reaching
// authentication, so probes and browsers are unaffected.
func (h *Handler) StreamRoute(authMiddlewares []fiber.Handler) []fiber.Handler {
	gate := func(c *fiber.Ctx) error {
		if !WantsEventStream(c) {
			return h.MethodNotAllowed(c)
		}
		return c.Next()
	}
	chain := make([]fiber.Handler, 0, len(authMiddlewares)+2)
	chain = append(chain, gate)
	chain = append(chain, authMiddlewares...)
	return append(chain, h.Stream)
}
