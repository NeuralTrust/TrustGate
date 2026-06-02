package auth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteAuthHandler struct {
	deleter appauth.Deleter
}

func NewDeleteAuthHandler(deleter appauth.Deleter) *DeleteAuthHandler {
	return &DeleteAuthHandler{deleter: deleter}
}

func (h *DeleteAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
