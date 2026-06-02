package backend

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteBackendHandler struct {
	deleter appbackend.Deleter
}

func NewDeleteBackendHandler(deleter appbackend.Deleter) *DeleteBackendHandler {
	return &DeleteBackendHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a backend
// @Description  Deletes a backend from a gateway.
// @Tags         backends
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        id          path  string  true  "Backend id"  format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/backends/{id} [delete]
func (h *DeleteBackendHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.BackendKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
