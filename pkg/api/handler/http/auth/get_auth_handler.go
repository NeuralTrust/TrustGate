package auth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	"github.com/gofiber/fiber/v2"
)

type GetAuthHandler struct {
	finder appauth.Finder
}

func NewGetAuthHandler(finder appauth.Finder) *GetAuthHandler {
	return &GetAuthHandler{finder: finder}
}

func (h *GetAuthHandler) Handle(c *fiber.Ctx) error {
	_, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	a, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromAuth(a))
}
