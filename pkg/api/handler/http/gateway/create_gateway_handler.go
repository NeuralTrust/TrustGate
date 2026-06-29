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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type CreateGatewayHandler struct {
	creator       appgateway.Creator
	baseDomain    string
	mcpBaseDomain string
}

func NewCreateGatewayHandler(creator appgateway.Creator, baseDomain, mcpBaseDomain string) *CreateGatewayHandler {
	return &CreateGatewayHandler{creator: creator, baseDomain: baseDomain, mcpBaseDomain: mcpBaseDomain}
}

// Handle godoc
// @Summary      Create a gateway
// @Description  Creates a new gateway.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway  body      request.CreateGatewayRequest  true  "Gateway to create"
// @Success      201      {object}  response.GatewayResponse
// @Failure      400      {object}  helpers.ErrorBody
// @Failure      401      {object}  helpers.ErrorBody
// @Failure      409      {object}  helpers.ErrorBody
// @Router       /v1/gateways [post]
func (h *CreateGatewayHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	g, err := h.creator.Create(c.UserContext(), appgateway.CreateInput{
		Slug:            req.Slug,
		Domain:          req.Domain,
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
}
