package backend

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	"github.com/gofiber/fiber/v2"
)

type DeleteBackendHandler struct {
	deleter appbackend.Deleter
}

func NewDeleteBackendHandler(deleter appbackend.Deleter) *DeleteBackendHandler {
	return &DeleteBackendHandler{deleter: deleter}
}

func (h *DeleteBackendHandler) Handle(c *fiber.Ctx) error {
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
