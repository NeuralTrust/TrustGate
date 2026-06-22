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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateConsumerHandler struct {
	updater appconsumer.Updater
}

func NewUpdateConsumerHandler(updater appconsumer.Updater) *UpdateConsumerHandler {
	return &UpdateConsumerHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a consumer
// @Description  Updates an existing consumer.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                         true  "Gateway id"   format(uuid)
// @Param        id          path      string                         true  "Consumer id"  format(uuid)
// @Param        body        body      request.UpdateConsumerRequest  true  "Consumer fields to update"
// @Success      200         {object}  response.ConsumerResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id} [put]
func (h *UpdateConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateConsumerRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	fallback, err := req.ToFallback()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	lbConfig, err := req.ToLBConfig()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	modelPolicies, err := req.ToModelPolicies()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	toolkit, err := req.ToToolkit()
	if err != nil {
		return helpers.WriteError(c, err)
	}

	cons, err := h.updater.Update(c.UserContext(), appconsumer.UpdateInput{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          req.Name,
		Type:          req.ToType(),
		RoutingMode:   req.ToRoutingMode(),
		LBConfig:      lbConfig,
		Headers:       req.Headers,
		Active:        req.Active,
		Fallback:      fallback,
		ModelPolicies: modelPolicies,
		Toolkit:       toolkit,
		FailMode:      req.ToFailMode(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromConsumer(cons))
}
