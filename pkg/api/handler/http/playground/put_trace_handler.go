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

package playground

import (
	"context"
	"encoding/json"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/gofiber/fiber/v2"
)

// TraceWriter persists a pushed playground trace under its TraceID.
type TraceWriter interface {
	Put(ctx context.Context, evt *events.Event) error
}

// PutTraceHandler ingests a playground trace pushed by a hybrid data plane, so
// the dashboard keeps reading traces from the control-plane store regardless of
// where the playground request actually ran.
type PutTraceHandler struct {
	writer TraceWriter
}

func NewPutTraceHandler(writer TraceWriter) *PutTraceHandler {
	return &PutTraceHandler{writer: writer}
}

// Handle godoc
// @Summary      Store a playground trace
// @Description  Ingests the metrics Event of a playground request served by an external (hybrid) data plane, keyed by its trace id, so the dashboard can fetch it from GET /v1/playground/traces/{trace_id}. The stored trace expires after the store TTL.
// @Tags         playground
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        trace_id  path      string        true  "Trace id (X-AG-Trace-Id of the playground request)"
// @Param        body      body      events.Event  true  "Metrics event captured for the playground request"
// @Success      204       "stored"
// @Failure      400       {object}  httpio.ErrorBody
// @Failure      401       {object}  httpio.ErrorBody
// @Failure      500       {object}  httpio.ErrorBody
// @Router       /v1/playground/traces/{trace_id} [put]
func (h *PutTraceHandler) Handle(c *fiber.Ctx) error {
	traceID := c.Params("trace_id")
	if traceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(httpio.ErrorBody{Error: "invalid_request", Message: "trace id is required"})
	}
	var evt events.Event
	if err := json.Unmarshal(c.Body(), &evt); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(httpio.ErrorBody{Error: "invalid_request", Message: "body must be a metrics event"})
	}
	if evt.TraceID == "" {
		evt.TraceID = traceID
	}
	if evt.TraceID != traceID {
		return c.Status(fiber.StatusBadRequest).JSON(httpio.ErrorBody{
			Error:   "invalid_request",
			Message: "event trace_id must match the path trace id",
		})
	}
	if err := h.writer.Put(c.UserContext(), &evt); err != nil {
		return httpio.WriteError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
