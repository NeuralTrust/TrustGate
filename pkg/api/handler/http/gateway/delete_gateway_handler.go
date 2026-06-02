package gateway

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteGatewayHandler struct {
	deleter appgateway.Deleter
}

func NewDeleteGatewayHandler(deleter appgateway.Deleter) *DeleteGatewayHandler {
	return &DeleteGatewayHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a gateway
// @Description  Deletes a gateway. Fails if it still has dependent resources.
// @Tags         gateways
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Gateway id"  format(uuid)
// @Success      204  "No Content"
// @Failure      400  {object}  helpers.ErrorBody
// @Failure      401  {object}  helpers.ErrorBody
// @Failure      404  {object}  helpers.ErrorBody
// @Failure      409  {object}  helpers.ErrorBody
// @Router       /v1/gateways/{id} [delete]
func (h *DeleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
