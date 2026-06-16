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

package gateway

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateGatewayHandler struct {
	updater       appgateway.Updater
	baseDomain    string
	mcpBaseDomain string
}

func NewUpdateGatewayHandler(updater appgateway.Updater, baseDomain, mcpBaseDomain string) *UpdateGatewayHandler {
	return &UpdateGatewayHandler{updater: updater, baseDomain: baseDomain, mcpBaseDomain: mcpBaseDomain}
}

// Handle godoc
// @Summary      Update a gateway
// @Description  Updates an existing gateway.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                        true  "Gateway id"  format(uuid)
// @Param        gateway  body      request.UpdateGatewayRequest  true  "Gateway fields to update"
// @Success      200      {object}  response.GatewayResponse
// @Failure      400      {object}  helpers.ErrorBody
// @Failure      401      {object}  helpers.ErrorBody
// @Failure      404      {object}  helpers.ErrorBody
// @Failure      409      {object}  helpers.ErrorBody
// @Router       /v1/gateways/{id} [put]
func (h *UpdateGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	g, err := h.updater.Update(c.UserContext(), appgateway.UpdateInput{
		ID:              id,
		Name:            req.Name,
		Slug:            req.Slug,
		Status:          req.Status,
		Domain:          req.Domain,
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
}
