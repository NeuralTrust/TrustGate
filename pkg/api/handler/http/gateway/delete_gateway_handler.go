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
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteGatewayHandler struct {
	deleter appgateway.Deleter
}

func NewDeleteGatewayHandler(deleter appgateway.Deleter) *DeleteGatewayHandler {
	return &DeleteGatewayHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a gateway
// @Description  Deletes a gateway and cascades the deletion to every resource that belongs to it (consumers, roles, policies, auths, registries and vault credentials).
// @Tags         gateways
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Gateway id"  format(uuid)
// @Success      204  "No Content"
// @Failure      400  {object}  helpers.ErrorBody
// @Failure      401  {object}  helpers.ErrorBody
// @Failure      404  {object}  helpers.ErrorBody
// @Router       /v1/gateways/{id} [delete]
func (h *DeleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
