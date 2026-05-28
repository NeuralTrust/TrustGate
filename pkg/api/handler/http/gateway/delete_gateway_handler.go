package gateway

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/gofiber/fiber/v2"
)

type DeleteGatewayHandler struct {
	deleter appgateway.Deleter
}

func NewDeleteGatewayHandler(deleter appgateway.Deleter) *DeleteGatewayHandler {
	return &DeleteGatewayHandler{deleter: deleter}
}

func (h *DeleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam(c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
