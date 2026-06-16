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
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetGatewayHandler struct {
	finder     appgateway.Finder
	baseDomain string
}

func NewGetGatewayHandler(finder appgateway.Finder, baseDomain string) *GetGatewayHandler {
	return &GetGatewayHandler{finder: finder, baseDomain: baseDomain}
}

// Handle godoc
// @Summary      Get a gateway
// @Description  Returns a single gateway by id.
// @Tags         gateways
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Gateway id"  format(uuid)
// @Success      200  {object}  response.GatewayResponse
// @Failure      400  {object}  helpers.ErrorBody
// @Failure      401  {object}  helpers.ErrorBody
// @Failure      404  {object}  helpers.ErrorBody
// @Router       /v1/gateways/{id} [get]
func (h *GetGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	g, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromDomain(g, h.baseDomain))
}
