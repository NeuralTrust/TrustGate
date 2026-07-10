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

package role

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role/response"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type CreateRoleHandler struct {
	creator approle.Creator
}

func NewCreateRoleHandler(creator approle.Creator) *CreateRoleHandler {
	return &CreateRoleHandler{creator: creator}
}

// Handle godoc
// @Summary      Create a role
// @Description  Creates a new role in a gateway. model_policies cannot be set on create; bind registries first, then update the role.
// @Tags         roles
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                   true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateRoleRequest  true  "Role to create"
// @Success      201         {object}  response.RoleResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles [post]
func (h *CreateRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.CreateRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}
	role, err := h.creator.Create(c.UserContext(), approle.CreateInput{
		GatewayID:   gatewayID,
		Name:        req.Name,
		OIDCMapping: req.OIDCMapping,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteCreated(c, response.FromRole(role))
}
