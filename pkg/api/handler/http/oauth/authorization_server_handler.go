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

// Handle godoc
// @Summary      OAuth authorization server metadata (RFC 8414)
// @Description  The gateway's own AS metadata: authorize/token/registration endpoints are served by the gateway and brokered to the configured corporate IdP. 404 until an oauth2 auth is configured.
// @Tags         oauth
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      404  {object}  helpers.ErrorBody
// @Router       /.well-known/oauth-authorization-server [get]
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
