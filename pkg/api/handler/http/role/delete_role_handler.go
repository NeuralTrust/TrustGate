package role

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteRoleHandler struct {
	deleter approle.Deleter
}

func NewDeleteRoleHandler(deleter approle.Deleter) *DeleteRoleHandler {
	return &DeleteRoleHandler{deleter: deleter}
}

func (h *DeleteRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RoleKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
