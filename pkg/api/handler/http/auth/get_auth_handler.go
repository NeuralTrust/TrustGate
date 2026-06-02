package auth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetAuthHandler struct {
	finder appauth.Finder
}

func NewGetAuthHandler(finder appauth.Finder) *GetAuthHandler {
	return &GetAuthHandler{finder: finder}
}

// Handle godoc
// @Summary      Get an auth
// @Description  Returns a single auth by id.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Auth id"     format(uuid)
// @Success      200         {object}  response.AuthResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths/{id} [get]
func (h *GetAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	a, err := h.finder.FindByID(c.UserContext(), gatewayID, id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromAuth(a))
}
