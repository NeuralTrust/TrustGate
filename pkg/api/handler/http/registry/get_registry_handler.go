package registry

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetRegistryHandler struct {
	finder appregistry.Finder
}

func NewGetRegistryHandler(finder appregistry.Finder) *GetRegistryHandler {
	return &GetRegistryHandler{finder: finder}
}

// Handle godoc
// @Summary      Get a backend
// @Description  Returns a single backend by id.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id} [get]
func (h *GetRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	b, err := h.finder.FindByID(c.UserContext(), gatewayID, id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromRegistry(b))
}
