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
	"encoding/json"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/gofiber/fiber/v2"
)

// subscriptionIDMetaKey correlates every frame on a listen stream with the
// request that opened it.
const subscriptionIDMetaKey = "io.modelcontextprotocol/subscriptionId"

// subscriptionFilter is what a client opts in to. Each type is opt-in and a
// server must not send one that was not asked for, so the ack names back only
// what this gateway both supports and was asked for.
type subscriptionFilter struct {
	ToolsListChanged      bool     `json:"toolsListChanged,omitempty"`
	PromptsListChanged    bool     `json:"promptsListChanged,omitempty"`
	ResourcesListChanged  bool     `json:"resourcesListChanged,omitempty"`
	ResourceSubscriptions []string `json:"resourceSubscriptions,omitempty"`
}

type subscriptionsListenParams struct {
	Notifications subscriptionFilter `json:"notifications"`
}

// handleSubscriptionsListen serves the 2026-07-28 replacement for the GET
// notification stream: one long-lived response that carries the change
// notifications the client opted in to.
//
// The gateway honors one of them, toolsListChanged, because one is what it
// watches: a user connecting an account or installing a server changes the
// tools they can call, and nothing else in the surface moves without the
// client having asked for it. A client that opts into the others is told in
// the acknowledgement that they are not on this stream, rather than left
// waiting for a notification that will never come.
func (h *Handler) handleSubscriptionsListen(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	skipMetrics(c)
	var params subscriptionsListenParams
	_ = json.Unmarshal(req.Params, &params)
	id := normalizeID(req.ID)

	if !params.Notifications.ToolsListChanged {
		// Nothing this gateway can send was asked for. Holding the stream open
		// would tie up a connection to deliver silence; the acknowledgement
		// says the honored set is empty and the request ends.
		return writeJSON(c, rawRPCResponse(req.ID, subscriptionsListenResult(id)))
	}

	snapshot := h.surfaceSnapshotFunc(c, rc)
	timings := h.timings
	if timings.poll <= 0 {
		timings = defaultStreamTimings
	}
	ack := sseFrame(subscriptionsAcknowledgedFrame(id, subscriptionFilter{ToolsListChanged: true}))
	change := sseFrame(toolsListChangedNotification(id))
	// The stream ends gracefully at the lifetime cap, and the revision has a
	// name for that: the result of the request that opened it. An abrupt close
	// carries no response, which is what a dropped connection already is.
	closing := sseFrame(rawRPCResponse(req.ID, subscriptionsListenResult(id)))

	c.Set(fiber.HeaderContentType, eventStreamContentType)
	c.Set(fiber.HeaderCacheControl, "no-cache, no-store")
	c.Set(fiber.HeaderConnection, "keep-alive")
	c.Set("X-Accel-Buffering", "no")
	c.Status(fiber.StatusOK)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		streamSurfaceChanges(w, snapshot, timings, surfaceStreamFrames{
			// The acknowledgement must be the first message on the stream, and
			// the change that follows it covers what moved while the client was
			// between streams — the same reason the GET pushes one on open.
			open:    []string{ack, change},
			change:  change,
			closing: closing,
		})
	})
	return nil
}

// surfaceSnapshotFunc reads the watched surface as it stands now, re-resolving
// the consumer each time so a binding an admin changes mid-stream is seen.
func (h *Handler) surfaceSnapshotFunc(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) func() string {
	principal := identity.PrincipalFromContext(c.UserContext())
	streamCtx := c.UserContext()
	path := strings.Clone(c.Path())
	gatewayID, _ := appconsumer.GatewayIDFromContext(streamCtx)
	return func() string {
		if h.surface == nil {
			return ""
		}
		ctx, cancel := context.WithTimeout(streamCtx, 5*time.Second)
		defer cancel()
		live := rc
		if next := h.liveConsumer(ctx, gatewayID, path); next != nil {
			live = next
		}
		return h.surface.WatchSnapshot(ctx, live, principal)
	}
}

func subscriptionsListenResult(id json.RawMessage) json.RawMessage {
	raw, err := json.Marshal(map[string]any{
		"resultType": resultTypeComplete,
		"_meta": map[string]any{
			subscriptionIDMetaKey: json.RawMessage(id),
			modernServerInfoMetaKey: map[string]any{
				"name":    serverName,
				"version": serverVersion,
			},
		},
	})
	if err != nil {
		return json.RawMessage(`{"resultType":"complete"}`)
	}
	return raw
}

func subscriptionsAcknowledgedFrame(id json.RawMessage, honored subscriptionFilter) any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/subscriptions/acknowledged",
		"params": map[string]any{
			"notifications": honored,
			"_meta":         map[string]any{subscriptionIDMetaKey: json.RawMessage(id)},
		},
	}
}

func toolsListChangedNotification(id json.RawMessage) any {
	return map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/tools/list_changed",
		"params": map[string]any{
			"_meta": map[string]any{subscriptionIDMetaKey: json.RawMessage(id)},
		},
	}
}

// sseFrame encodes one message for the response stream. A frame that cannot be
// encoded is dropped rather than written half-formed: a truncated frame would
// desynchronise every message after it.
func sseFrame(message any) string {
	payload, err := json.Marshal(message)
	if err != nil {
		return ""
	}
	return "event: message\ndata: " + string(payload) + "\n\n"
}
