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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// AgentCardHandler compares an A2A registry's live card with the pinned one
// and pins a reviewed change.
type AgentCardHandler struct {
	refresh appregistry.RefreshAgentCard
	approve appregistry.ApproveAgentCard
}

func NewAgentCardHandler(refresh appregistry.RefreshAgentCard, approve appregistry.ApproveAgentCard) *AgentCardHandler {
	return &AgentCardHandler{refresh: refresh, approve: approve}
}

// Refresh godoc
// @Summary      Compare an agent's live card with the pinned one
// @Description  Reads the live card of an A2A registry and reports whether it changed, which top-level fields and which skills. Writes nothing.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  response.AgentCardRefreshResponse
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/agent-card/refresh [post]
func (h *AgentCardHandler) Refresh(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	refresh, err := h.refresh.Refresh(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromAgentCardRefresh(refresh))
}

// Approve godoc
// @Summary      Pin a reviewed agent card
// @Description  Reads the live card again and pins it only if its digest is the one sent. Approving the pinned digest changes nothing.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                           true  "Gateway id"   format(uuid)
// @Param        id          path      string                           true  "Registry id"  format(uuid)
// @Param        body        body      request.ApproveAgentCardRequest  true  "Reviewed digest"
// @Success      200         {object}  response.RegistryResponse
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody  "The live card no longer has that digest"
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/agent-card/approve [post]
func (h *AgentCardHandler) Approve(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.ApproveAgentCardRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}
	reg, err := h.approve.Approve(c.UserContext(), gatewayID, id, req.Digest)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromRegistry(reg))
}
