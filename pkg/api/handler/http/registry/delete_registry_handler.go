package registry

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteRegistryHandler struct {
	deleter appregistry.Deleter
}

func NewDeleteRegistryHandler(deleter appregistry.Deleter) *DeleteRegistryHandler {
	return &DeleteRegistryHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a backend
// @Description  Deletes a backend from a gateway.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        id          path  string  true  "Registry id"  format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id} [delete]
func (h *DeleteRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
