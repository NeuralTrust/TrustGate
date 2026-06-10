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
