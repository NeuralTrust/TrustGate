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

package a2a

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

// Handler serves the agent plane: the agent card and the JSON-RPC endpoint.
type Handler struct {
	forwarder *appa2a.Forwarder
}

// NewHandler builds the agent plane's handler.
func NewHandler(forwarder *appa2a.Forwarder) *Handler {
	return &Handler{forwarder: forwarder}
}

// Card serves the pinned card of the agent the path names, rewritten to point
// at the gateway.
func (h *Handler) Card(c *fiber.Ctx) error {
	rc, agent, ok := resolve(c)
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	target := agent.A2ATarget
	endpoint := c.BaseURL() + "/" + rc.Consumer.Slug + "/agents/" + agent.ID.String()
	card, err := appa2a.RenderCard(target.Card, appa2a.Version(target.ProtocolVersion), endpoint,
		target.Provider == registrydomain.A2AProviderVertexAgentEngine)
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(card)
}

// RPC forwards a JSON-RPC call to the agent the path names.
func (h *Handler) RPC(c *fiber.Ctx) error {
	rc, agent, ok := resolve(c)
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if !strings.HasPrefix(c.Get(fiber.HeaderContentType), fiber.MIMEApplicationJSON) {
		return send(c, nil, nil, appa2a.InvalidRequest())
	}
	body := bytes.Clone(c.Body())
	req, err := appa2a.Decode(body)
	if err != nil {
		var id json.RawMessage
		if req != nil {
			id = req.ID
		}
		rpcErr, _ := err.(*appa2a.RPCError)
		return send(c, id, nil, rpcErr)
	}
	header := http.Header{}
	for name, value := range c.Request().Header.All() {
		header.Add(string(name), string(value))
	}
	ctx := c.UserContext()
	stampTrace(ctx, rc)
	x, rpcErr := h.forwarder.Prepare(ctx, &appa2a.Call{
		Consumer:  rc,
		Agent:     agent,
		Principal: identity.PrincipalFromContext(ctx),
		Request:   req,
		Body:      body,
		Header:    header,
	})
	if rpcErr != nil {
		return send(c, req.ID, nil, rpcErr)
	}
	if x.Streams() {
		return stream(c, req.ID, x)
	}
	result, rpcErr := x.Send(ctx)
	return send(c, req.ID, result, rpcErr)
}

// streamWriteGrace is how long past a stream's deadline its last event may
// take to write.
const streamWriteGrace = 10 * time.Second

// stream answers with the agent's events as server-sent events, flushed one
// by one. A failed write, a caller that left, ends the stream and the
// upstream call.
func stream(c *fiber.Ctx, id json.RawMessage, x *appa2a.Exchange) error {
	ctx := c.UserContext()
	s, rpcErr := x.Open(ctx)
	if rpcErr != nil {
		return send(c, id, nil, rpcErr)
	}
	_ = c.Context().SetWriteDeadline(s.Deadline().Add(streamWriteGrace))
	rt := trace.FromContext(ctx)
	if rt != nil {
		rt.AddAsync()
	}
	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-cache, no-store")
	c.Set("X-Accel-Buffering", "no")
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		if rt != nil {
			defer rt.Done()
		}
		s.Run(ctx, id, func(frame []byte) error {
			_, _ = w.WriteString("data: ")
			_, _ = w.Write(frame)
			_, _ = w.WriteString("\n\n")
			return w.Flush()
		})
	})
	return nil
}

// stampTrace records on the request's trace the consumer, the credential and
// the principal the call runs as.
func stampTrace(ctx context.Context, rc *appconsumer.RoutableConsumer) {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return
	}
	rt.SetConsumer(rc.Consumer.ID.String(), rc.Consumer.Name)
	if authID, ok := appconsumer.AuthIDFromContext(ctx); ok {
		rt.SetAuthID(authID.String())
	}
	if p := identity.PrincipalFromContext(ctx); p != nil {
		rt.SetPrincipalIdentity(p.Subject, string(p.Method), p.Email())
	}
}

func resolve(c *fiber.Ctx) (*appconsumer.RoutableConsumer, *registrydomain.Registry, bool) {
	rc, ok := appconsumer.ConsumerFromContext(c.UserContext())
	if !ok {
		return nil, nil, false
	}
	name, err := url.PathUnescape(c.Params("agent"))
	if err != nil {
		return nil, nil, false
	}
	agent, ok := appa2a.ResolveAgent(rc, name)
	return rc, agent, ok
}

func send(c *fiber.Ctx, id, result json.RawMessage, rpcErr *appa2a.RPCError) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(appa2a.Response(id, result, rpcErr))
}
