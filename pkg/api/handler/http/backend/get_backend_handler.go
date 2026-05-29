package backend

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	"github.com/gofiber/fiber/v2"
)

type GetBackendHandler struct {
	finder appbackend.Finder
}

func NewGetBackendHandler(finder appbackend.Finder) *GetBackendHandler {
	return &GetBackendHandler{finder: finder}
}

func (h *GetBackendHandler) Handle(c *fiber.Ctx) error {
	_, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	b, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromBackend(b))
}
