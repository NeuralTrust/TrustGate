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
