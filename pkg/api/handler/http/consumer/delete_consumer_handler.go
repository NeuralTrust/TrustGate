package consumer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteConsumerHandler struct {
	deleter appconsumer.Deleter
}

func NewDeleteConsumerHandler(deleter appconsumer.Deleter) *DeleteConsumerHandler {
	return &DeleteConsumerHandler{deleter: deleter}
}

func (h *DeleteConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
