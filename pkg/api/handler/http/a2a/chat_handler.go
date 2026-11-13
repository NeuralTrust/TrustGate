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
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ChatCompletions answers an OpenAI chat completions request with the agent
// the path names: its last user message goes to the agent as one A2A message
// and the answer comes back as a chat completion, or as chunks with
// "stream": true. See appa2a.ChatCall for the conversation.
func (h *Handler) ChatCompletions(c *fiber.Ctx) error {
	rc, agent, ok := resolve(c)
	if !ok {
		return chatError(c, http.StatusNotFound, "not_found", "No agent at this path.")
	}
	var chat appa2a.ChatRequest
	if err := json.Unmarshal(c.Body(), &chat); err != nil {
		return chatError(c, http.StatusBadRequest, "invalid_request_error", "The body is not a chat completions request.")
	}
	text, ok := chat.LastUserText()
	if !ok {
		return chatError(c, http.StatusBadRequest, "invalid_request_error", "messages needs a user message with text.")
	}
	target := agent.A2ATarget
	streaming := chat.Stream && appa2a.CanStream(target)
	body := appa2a.ChatCall(target.ProtocolVersion, streaming, text, strings.TrimSpace(c.Get(appa2a.HeaderA2AContextID)))
	req, rpcErr := appa2a.Decode(body)
	if rpcErr != nil {
		return chatFailure(c, rpcErr)
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
		return chatFailure(c, rpcErr)
	}
	completion := chatCompletion{id: "chatcmpl-" + uuid.NewString(), model: agent.Name, created: time.Now().Unix()}
	if streaming {
		return chatStream(c, x, completion)
	}
	result, rpcErr := x.Send(ctx)
	if rpcErr != nil {
		return chatFailure(c, rpcErr)
	}
	answer, contextID := appa2a.ChatText(target.ProtocolVersion, result)
	if contextID != "" {
		c.Set(appa2a.HeaderA2AContextID, contextID)
	}
	if chat.Stream {
		// The agent does not stream: the answer goes as one chunk.
		return chatChunks(c, completion, answer, contextID)
	}
	input, output := x.Tokens()
	return c.JSON(completion.message(answer, contextID, input, output))
}

type chatCompletion struct {
	id      string
	model   string
	created int64
}

func (cc chatCompletion) message(text, contextID string, input, output int) map[string]any {
	out := map[string]any{
		"id": cc.id, "object": "chat.completion", "created": cc.created, "model": cc.model,
		"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
	}
	if contextID != "" {
		out["a2a_context_id"] = contextID
	}
	if input+output > 0 {
		out["usage"] = map[string]int{"prompt_tokens": input, "completion_tokens": output, "total_tokens": input + output}
	}
	return out
}

// chunk is a chat.completion.chunk carrying delta, or the end of the answer
// when finish is set.
func (cc chatCompletion) chunk(delta, contextID string, finish bool) []byte {
	choice := map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": nil}
	if delta != "" {
		choice["delta"] = map[string]any{"role": "assistant", "content": delta}
	}
	if finish {
		choice["finish_reason"] = "stop"
	}
	out := map[string]any{"id": cc.id, "object": "chat.completion.chunk", "created": cc.created, "model": cc.model, "choices": []map[string]any{choice}}
	if contextID != "" {
		out["a2a_context_id"] = contextID
	}
	raw, _ := json.Marshal(out)
	return raw
}

func setEventStream(c *fiber.Ctx) {
	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-cache, no-store")
	c.Set("X-Accel-Buffering", "no")
}

func writeEvent(w *bufio.Writer, data []byte) error {
	_, _ = w.WriteString("data: ")
	_, _ = w.Write(data)
	_, _ = w.WriteString("\n\n")
	return w.Flush()
}

// chatChunks answers a buffered answer as a stream: one chunk, the end, [DONE].
func chatChunks(c *fiber.Ctx, cc chatCompletion, text, contextID string) error {
	setEventStream(c)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		_ = writeEvent(w, cc.chunk(text, contextID, false))
		_ = writeEvent(w, cc.chunk("", contextID, true))
		_ = writeEvent(w, []byte("[DONE]"))
	})
	return nil
}

// chatStream relays the agent's events as chunks of its text. An error event
// ends the stream with an OpenAI error object.
func chatStream(c *fiber.Ctx, x *appa2a.Exchange, cc chatCompletion) error {
	ctx := c.UserContext()
	s, rpcErr := x.Open(ctx)
	if rpcErr != nil {
		return chatFailure(c, rpcErr)
	}
	if err := c.Context().SetWriteDeadline(s.Deadline().Add(streamWriteGrace)); err != nil {
		slog.WarnContext(ctx, "a2a chat stream write deadline not set", slog.String("error", err.Error()))
	}
	rt := trace.FromContext(ctx)
	if rt != nil {
		rt.AddAsync()
	}
	version := x.Version()
	setEventStream(c)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		if rt != nil {
			defer rt.Done()
		}
		contextID, failed := "", false
		s.Run(ctx, json.RawMessage(`"`+cc.id+`"`), func(frame []byte) error {
			var event struct {
				Result json.RawMessage  `json:"result"`
				Error  *appa2a.RPCError `json:"error"`
			}
			_ = json.Unmarshal(frame, &event)
			if event.Error != nil {
				failed = true
				_, kind := appa2a.ChatStatus(event.Error)
				raw, _ := json.Marshal(map[string]any{"error": map[string]any{"message": event.Error.Message, "type": kind, "code": event.Error.Code}})
				return writeEvent(w, raw)
			}
			text, named := appa2a.ChatText(version, event.Result)
			if named != "" {
				contextID = named
			}
			if text == "" {
				return nil
			}
			return writeEvent(w, cc.chunk(text, contextID, false))
		})
		if !failed {
			_ = writeEvent(w, cc.chunk("", contextID, true))
		}
		_ = writeEvent(w, []byte("[DONE]"))
	})
	return nil
}

func chatFailure(c *fiber.Ctx, e *appa2a.RPCError) error {
	status, kind := appa2a.ChatStatus(e)
	return chatError(c, status, kind, e.Message)
}

func chatError(c *fiber.Ctx, status int, kind, message string) error {
	return c.Status(status).JSON(map[string]any{"error": map[string]any{"message": message, "type": kind}})
}
