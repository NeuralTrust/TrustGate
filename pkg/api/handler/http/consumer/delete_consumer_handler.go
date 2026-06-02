package consumer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/gofiber/fiber/v2"
)

type DeleteConsumerHandler struct {
	deleter appconsumer.Deleter
}

func NewDeleteConsumerHandler(deleter appconsumer.Deleter) *DeleteConsumerHandler {
	return &DeleteConsumerHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a consumer
// @Description  Deletes a consumer from a gateway.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id} [delete]
func (h *DeleteConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
