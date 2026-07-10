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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteConsumerHandler struct {
	deleter appconsumer.Deleter
}

func NewDeleteConsumerHandler(deleter appconsumer.Deleter) *DeleteConsumerHandler {
	return &DeleteConsumerHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a consumer
// @Description  Deletes a consumer from a gateway.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id} [delete]
func (h *DeleteConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}
