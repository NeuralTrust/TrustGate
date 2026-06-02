package gateway

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetGatewayHandler struct {
	finder appgateway.Finder
}

func NewGetGatewayHandler(finder appgateway.Finder) *GetGatewayHandler {
	return &GetGatewayHandler{finder: finder}
}

func (h *GetGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	g, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromDomain(g))
}
