package auth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	"github.com/gofiber/fiber/v2"
)

type DeleteAuthHandler struct {
	deleter appauth.Deleter
}

func NewDeleteAuthHandler(deleter appauth.Deleter) *DeleteAuthHandler {
	return &DeleteAuthHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete an auth
// @Description  Deletes an auth from a gateway.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        id          path  string  true  "Auth id"     format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths/{id} [delete]
func (h *DeleteAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
