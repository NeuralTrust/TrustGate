package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/gofiber/fiber/v2"
)

type DeletePolicyHandler struct {
	deleter apppolicy.Deleter
}

func NewDeletePolicyHandler(deleter apppolicy.Deleter) *DeletePolicyHandler {
	return &DeletePolicyHandler{deleter: deleter}
}

func (h *DeletePolicyHandler) Handle(c *fiber.Ctx) error {
	if _, err := helpers.ParseUUIDParam(c, "gateway_id"); err != nil {
		return helpers.WriteError(c, err)
	}
	id, err := helpers.ParseUUIDParam(c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
