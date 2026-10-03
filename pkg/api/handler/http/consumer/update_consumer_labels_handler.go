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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateConsumerLabelsHandler struct {
	updater appconsumer.LabelUpdater
}

func NewUpdateConsumerLabelsHandler(updater appconsumer.LabelUpdater) *UpdateConsumerLabelsHandler {
	return &UpdateConsumerLabelsHandler{updater: updater}
}

// Handle godoc
// @Summary      Replace a consumer's traffic labels
// @Description  Replaces the whole list of traffic labels a consumer's chat requests are classified against. Labels are projected from the app's catalog: ids are opaque and must be unique, names are unique ignoring case. At most 10 labels; name 1-64 characters, instructions 1-2000, up to 5 examples of 1-500. Send `{"labels": []}` to clear. Only LLM consumers can hold labels. Returns the full consumer.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                               true  "Gateway id"   format(uuid)
// @Param        id          path      string                               true  "Consumer id"  format(uuid)
// @Param        body        body      request.UpdateConsumerLabelsRequest  true  "The consumer's labels"
// @Success      200         {object}  response.ConsumerResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/labels [put]
func (h *UpdateConsumerLabelsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.UpdateConsumerLabelsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	cons, err := h.updater.UpdateLabels(c.UserContext(), appconsumer.UpdateLabelsInput{
		ID:        id,
		GatewayID: gatewayID,
		Labels:    req.ToDomain(),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromConsumer(cons))
}
