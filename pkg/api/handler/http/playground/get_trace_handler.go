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

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/gofiber/fiber/v2"
)

// TraceFinder retrieves a stored playground trace by its TraceID (the
// X-Request-Id the proxy echoed to the client).
type TraceFinder interface {
	Find(ctx context.Context, traceID string) (*events.Event, error)
}

type GetTraceHandler struct {
	finder TraceFinder
}

func NewGetTraceHandler(finder TraceFinder) *GetTraceHandler {
	return &GetTraceHandler{finder: finder}
}

// Handle godoc
// @Summary      Get a playground trace
// @Description  Returns the metrics Event captured for a playground request, keyed by the X-Request-Id returned in the proxy response. Traces expire after a short TTL.
// @Tags         playground
// @Produce      json
// @Security     BearerAuth
// @Param        trace_id  path      string  true  "Trace id (X-Request-Id from the proxy response)"
// @Success      200       {object}  events.Event
// @Failure      401       {object}  helpers.ErrorBody
// @Failure      404       {object}  helpers.ErrorBody
// @Failure      500       {object}  helpers.ErrorBody
// @Router       /v1/playground/traces/{trace_id} [get]
func (h *GetTraceHandler) Handle(c *fiber.Ctx) error {
	traceID := c.Params("trace_id")
	if traceID == "" {
		return c.Status(fiber.StatusNotFound).JSON(helpers.ErrorBody{Error: "not_found"})
	}
	evt, err := h.finder.Find(c.UserContext(), traceID)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if evt == nil {
		return c.Status(fiber.StatusNotFound).JSON(helpers.ErrorBody{Error: "not_found"})
	}
	return helpers.WriteOK(c, evt)
}
