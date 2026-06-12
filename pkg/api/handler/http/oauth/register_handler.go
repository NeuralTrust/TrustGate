package oauth

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const RegisterPath = "/oauth/register"

type RegisterHandler struct {
	metadata appoauth.MetadataService
}

func NewRegisterHandler(metadata appoauth.MetadataService) *RegisterHandler {
	return &RegisterHandler{metadata: metadata}
}

func (h *RegisterHandler) Handle(c *fiber.Ctx) error {
	var req appoauth.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid client registration request")
	}
	res, err := h.metadata.RegisterClient(c.UserContext(), req)
	if err != nil {
		var oauthErr *appoauth.OAuthError
		if errors.Is(err, appoauth.ErrRegistrationUnavailable) || errors.As(err, &oauthErr) {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, res)
}
