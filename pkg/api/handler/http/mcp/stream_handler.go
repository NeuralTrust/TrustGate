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
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
// The same is true of an admin attaching or detaching a registry on a custom
// consumer. This stream watches credentials, Store installs, and the consumer's
// current MCP bindings, and pushes notifications/tools/list_changed when any
// of them change — the only signal that makes a client re-list without
// reconnecting. It also pushes one on GET open so a recycled stream still
// refreshes a client that missed a change while the previous GET was down.
func (h *Handler) Stream(c *fiber.Ctx) error {
	skipMetrics(c)
	if !WantsEventStream(c) {
		return h.MethodNotAllowed(c)
	}
	rc, err := resolveMCPConsumer(c)
	if err != nil {
		return err
	}
	principal := identity.PrincipalFromContext(c.UserContext())
	streamCtx := c.UserContext()
	path := c.Path()
	gatewayID, _ := appconsumer.GatewayIDFromContext(streamCtx)
	snapshot := func() string {
		ctx, cancel := context.WithTimeout(streamCtx, 5*time.Second)
		defer cancel()
		if h.surface == nil {
			return ""
		}
		live := rc
		if next := h.liveConsumer(ctx, gatewayID, path); next != nil {
			live = next
		}
		return h.surface.WatchSnapshot(ctx, live, principal)
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

// streamToolChanges holds the stream open, pushing a notification whenever the
// watched surface changes. It returns when the client goes away (a write to a
// closed connection fails) or the lifetime cap expires, at which point the
// client is free to open a new stream.
func streamToolChanges(w *bufio.Writer, snapshot func() string, timings streamTimings) {
	previous := snapshot()
	if !flushFrame(w, streamKeepAliveFrame) {
		return
	}
	// The GET recycles every ~45s. If the surface changed while the previous
	// stream was down, previous already equals current and a delta-only watch
	// would stay quiet — the client keeps the tools/list from last time.
	if !flushFrame(w, toolsListChangedFrame) {
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

func (h *Handler) liveConsumer(ctx context.Context, gatewayID ids.GatewayID, path string) *appconsumer.RoutableConsumer {
	if h == nil || h.consumers == nil || gatewayID.IsNil() {
		return nil
	}
	data, err := h.consumers.FindByGateway(ctx, gatewayID)
	if err != nil || data == nil {
		return nil
	}
	rc, ok := data.MatchPath(path)
	if !ok {
		return nil
	}
	return rc
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
