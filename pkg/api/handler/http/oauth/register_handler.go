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

// Handle godoc
// @Summary      Dynamic client registration (RFC 7591)
// @Description  Registers an MCP client. Corporate IdPs rarely allow open DCR, so the admin-registered public client is returned and PKCE secures the authorization flow.
// @Tags         oauth
// @Accept       json
// @Produce      json
// @Param        request  body      appoauth.RegisterRequest  true  "Client registration request"
// @Success      201      {object}  appoauth.RegisterResponse
// @Failure      400      {object}  helpers.ErrorBody
// @Router       /oauth/register [post]
func (h *RegisterHandler) Handle(c *fiber.Ctx) error {
	var req appoauth.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid client registration request")
	}
	res, err := h.metadata.RegisterClient(c.UserContext(), req)
	if err != nil {
		if errors.Is(err, appoauth.ErrRegistrationUnavailable) {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, res)
}
