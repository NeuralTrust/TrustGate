package auth

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateAuthHandler struct {
	updater appauth.Updater
}

func NewUpdateAuthHandler(updater appauth.Updater) *UpdateAuthHandler {
	return &UpdateAuthHandler{updater: updater}
}

func (h *UpdateAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	a, err := h.updater.Update(c.UserContext(), appauth.UpdateInput{
		ID:        id,
		GatewayID: gatewayID,
		Name:      req.Name,
		Type:      domain.Type(req.Type),
		Enabled:   req.IsEnabled(),
		Config:    req.Config.ToDomain(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromAuth(a))
}
