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

package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DuplicatePolicyHandler struct {
	duplicator apppolicy.Duplicator
}

func NewDuplicatePolicyHandler(duplicator apppolicy.Duplicator) *DuplicatePolicyHandler {
	return &DuplicatePolicyHandler{duplicator: duplicator}
}

// Handle godoc
// @Summary      Duplicate a policy
// @Description  Creates a copy of an existing policy. The new policy reuses the plugin configuration (slug, settings, stages, enabled, priority, parallel) with a fresh id and an auto-generated name (suffix 2, 3, 4...). The copy has no consumer associations and is not global.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      201         {object}  response.PolicyResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id}/duplicate [post]
func (h *DuplicatePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	p, err := h.duplicator.Duplicate(c.UserContext(), gatewayID, id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromPolicy(p))
}
