package role

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/response"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateRoleHandler struct {
	updater approle.Updater
}

func NewUpdateRoleHandler(updater approle.Updater) *UpdateRoleHandler {
	return &UpdateRoleHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a role
// @Description  Updates a role. model_policies may only reference registries already attached to the role.
// @Tags         roles
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                   true  "Gateway id"  format(uuid)
// @Param        id          path      string                   true  "Role id"     format(uuid)
// @Param        body        body      request.UpdateRoleRequest  true  "Role fields to update"
// @Success      200         {object}  response.RoleResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles/{id} [put]
func (h *UpdateRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RoleKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	var req request.UpdateRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}
	modelPolicies, err := req.ToModelPolicies()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	role, err := h.updater.Update(c.UserContext(), approle.UpdateInput{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          req.Name,
		ModelPolicies: modelPolicies,
		McpPolicies:   req.McpPolicies,
		IDPMapping:    req.IDPMapping,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromRole(role))
}
