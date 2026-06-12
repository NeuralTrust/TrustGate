package oauth

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const WellKnownAuthorizationServerPath = "/.well-known/oauth-authorization-server"

type AuthorizationServerHandler struct {
	metadata appoauth.MetadataService
}

func NewAuthorizationServerHandler(metadata appoauth.MetadataService) *AuthorizationServerHandler {
	return &AuthorizationServerHandler{metadata: metadata}
}

func (h *AuthorizationServerHandler) Handle(c *fiber.Ctx) error {
	doc, err := h.metadata.AuthorizationServer(c.UserContext(), c.BaseURL())
	if err != nil {
		if errors.Is(err, appoauth.ErrNoAuthorizationServer) || errors.Is(err, appoauth.ErrAmbiguousAuthorizationServer) {
			return fiber.NewError(fiber.StatusNotFound, err.Error())
		}
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, doc)
}
