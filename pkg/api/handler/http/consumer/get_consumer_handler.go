package consumer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/gofiber/fiber/v2"
)

type GetConsumerHandler struct {
	finder appconsumer.Finder
}

func NewGetConsumerHandler(finder appconsumer.Finder) *GetConsumerHandler {
	return &GetConsumerHandler{finder: finder}
}

func (h *GetConsumerHandler) Handle(c *fiber.Ctx) error {
	if _, err := helpers.ParseUUIDParam(c, "gateway_id"); err != nil {
		return helpers.WriteError(c, err)
	}
	id, err := helpers.ParseUUIDParam(c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	cons, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromConsumer(cons))
}
