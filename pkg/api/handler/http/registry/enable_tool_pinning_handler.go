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

package registry

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type EnableToolPinningHandler struct {
	tools appregistry.PinnedToolService
}

func NewEnableToolPinningHandler(tools appregistry.PinnedToolService) *EnableToolPinningHandler {
	return &EnableToolPinningHandler{tools: tools}
}

// Handle godoc
// @Summary      Enable tool pinning with a confirmed list
// @Description  Approves exactly the listed tools (fingerprints are computed by the server) and sets the registry's tool_policy to pinned, in one transaction, then publishes a new config snapshot. An empty list is allowed. Only MCP registries can be pinned; an LLM registry is 422. Disabling pinning is a plain registry update with tool_policy=auto.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                            true  "Gateway id"   format(uuid)
// @Param        id          path      string                            true  "Registry id"  format(uuid)
// @Param        body        body      request.EnableToolPinningRequest  true  "The confirmed tool list"
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/tool-pinning [put]
func (h *EnableToolPinningHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.EnableToolPinningRequest
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}
	tools, err := req.ToCandidates()
	if err != nil {
		if errors.Is(err, request.ErrBadToolPinning) {
			return badRequest(c, err.Error())
		}
		return httpio.WriteError(c, err)
	}
	reg, err := h.tools.Pin(c.UserContext(), appregistry.PinToolsInput{
		GatewayID:  gatewayID,
		RegistryID: id,
		Tools:      tools,
		DecidedBy:  callerActor(c),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromRegistry(reg))
}
