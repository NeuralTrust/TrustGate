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

package consumer

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type CreateConsumerHandler struct {
	creator appconsumer.Creator
}

func NewCreateConsumerHandler(creator appconsumer.Creator) *CreateConsumerHandler {
	return &CreateConsumerHandler{creator: creator}
}

// Handle godoc
// @Summary      Create a consumer
// @Description  Creates a new consumer in a gateway.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                         true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateConsumerRequest  true  "Consumer to create"
// @Success      201         {object}  response.ConsumerResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers [post]
func (h *CreateConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.CreateConsumerRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}
	fallback, err := req.ToFallback()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	mcp, err := req.ToMCPPolicy()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	lbConfig, err := req.ToLBConfig()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	registryIDs, registryWeights, modelPolicies, err := req.ToRegistryBindings()
	if err != nil {
		return httpio.WriteError(c, err)
	}
	roleIDs, err := req.ToRoleIDs()
	if err != nil {
		return httpio.WriteError(c, err)
	}

	cons, err := h.creator.Create(c.UserContext(), appconsumer.CreateInput{
		GatewayID:       gatewayID,
		Name:            req.Name,
		Type:            req.ToType(),
		RoutingMode:     req.ToRoutingMode(),
		LBConfig:        lbConfig,
		Headers:         req.Headers,
		Active:          req.Active,
		Fallback:        fallback,
		RegistryIDs:     registryIDs,
		RegistryWeights: registryWeights,
		RoleIDs:         roleIDs,
		ModelPolicies:   modelPolicies,
		MCP:             mcp,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.FromConsumer(cons))
}
