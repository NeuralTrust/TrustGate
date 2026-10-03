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

type UpdateConsumerLabelSetsHandler struct {
	updater appconsumer.LabelSetUpdater
}

func NewUpdateConsumerLabelSetsHandler(updater appconsumer.LabelSetUpdater) *UpdateConsumerLabelSetsHandler {
	return &UpdateConsumerLabelSetsHandler{updater: updater}
}

// Handle godoc
// @Summary      Replace a consumer's traffic label sets
// @Description  Replaces all the traffic label sets a consumer's chat requests are classified against; each set yields at most one of its labels per request. Label sets are projected from the app's catalog: ids are opaque and must be unique, set names are unique ignoring case. At most 10 label sets; set name 1-64 characters, instructions 0-2000; 2 to 20 labels per set, label name 1-64 characters and unique in its set ignoring case, description 0-500. Send `{"label_sets": []}` to clear; the field is required. Only LLM consumers can hold label sets. Returns the full consumer.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                                  true  "Gateway id"   format(uuid)
// @Param        id          path      string                                  true  "Consumer id"  format(uuid)
// @Param        body        body      request.UpdateConsumerLabelSetsRequest  true  "The consumer's label sets"
// @Success      200         {object}  response.ConsumerResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/label-sets [put]
func (h *UpdateConsumerLabelSetsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.UpdateConsumerLabelSetsRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	cons, err := h.updater.UpdateLabelSets(c.UserContext(), appconsumer.UpdateLabelSetsInput{
		ID:        id,
		GatewayID: gatewayID,
		LabelSets: req.ToDomain(),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromConsumer(cons))
}
