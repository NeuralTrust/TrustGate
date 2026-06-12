package role

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/response"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
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
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles [post]
func (h *CreateRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	var req request.CreateRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}
	role, err := h.creator.Create(c.UserContext(), approle.CreateInput{
		GatewayID:   gatewayID,
		Name:        req.Name,
		McpPolicies: req.McpPolicies,
		IDPMapping:  req.IDPMapping,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromRole(role))
}
