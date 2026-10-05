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
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

type DecidePinnedToolsHandler struct {
	tools appregistry.PinnedToolService
}

func NewDecidePinnedToolsHandler(tools appregistry.PinnedToolService) *DecidePinnedToolsHandler {
	return &DecidePinnedToolsHandler{tools: tools}
}

// DecidePinnedToolsResponse reports how many distinct definitions were decided.
type DecidePinnedToolsResponse struct {
	Approved int `json:"approved"`
	Rejected int `json:"rejected"`
}

// Handle godoc
// @Summary      Approve or reject tool definitions of a pinned MCP registry
// @Description  Applies approvals and rejections atomically, recording the authenticated admin as the decider, and publishes a new config snapshot. A definition is identified by (name, fingerprint) as listed by pinned-tools. If any ref does not exist for the registry the call returns 422 and nothing is applied; a ref in both lists, an empty body or an oversized list is 400.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                              true  "Gateway id"   format(uuid)
// @Param        id          path      string                              true  "Registry id"  format(uuid)
// @Param        body        body      request.PinnedToolDecisionsRequest  true  "Definitions to approve and reject"
// @Success      200         {object}  DecidePinnedToolsResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/pinned-tools/decisions [post]
func (h *DecidePinnedToolsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.PinnedToolDecisionsRequest
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}
	if err := req.Validate(); err != nil {
		if errors.Is(err, request.ErrBadToolDecision) {
			return badRequest(c, err.Error())
		}
		return httpio.WriteError(c, err)
	}
	if err := h.tools.Decide(c.UserContext(), appregistry.DecideToolsInput{
		GatewayID:  gatewayID,
		RegistryID: id,
		Approve:    req.Approvals(),
		Reject:     req.Rejections(),
		DecidedBy:  callerActor(c),
	}); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, DecidePinnedToolsResponse{Approved: len(req.Approve), Rejected: len(req.Reject)})
}

func badRequest(c *fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusBadRequest).JSON(httpio.ErrorBody{Error: "invalid_request", Message: msg})
}

// callerActor is who made the call: the admin's email when the token carries
// one, else their id. It comes from the authenticated context, never the body.
func callerActor(c *fiber.Ctx) string {
	if email, ok := c.Locals(string(infracontext.UserEmailContextKey)).(string); ok && email != "" {
		return email
	}
	if id, ok := c.Locals(string(infracontext.UserIDContextKey)).(string); ok {
		return id
	}
	return ""
}
