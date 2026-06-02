package consumer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetConsumerHandler struct {
	finder appconsumer.Finder
}

func NewGetConsumerHandler(finder appconsumer.Finder) *GetConsumerHandler {
	return &GetConsumerHandler{finder: finder}
}

// Handle godoc
// @Summary      Get a consumer
// @Description  Returns a single consumer by id.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Consumer id"  format(uuid)
// @Success      200         {object}  response.ConsumerResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id} [get]
func (h *GetConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.ConsumerKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	cons, err := h.finder.FindByID(c.UserContext(), gatewayID, id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromConsumer(cons))
}
