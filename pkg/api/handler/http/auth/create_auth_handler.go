package auth

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

type CreateAuthHandler struct {
	creator appauth.Creator
}

func NewCreateAuthHandler(creator appauth.Creator) *CreateAuthHandler {
	return &CreateAuthHandler{creator: creator}
}

func (h *CreateAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreateAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	a, err := h.creator.Create(c.UserContext(), appauth.CreateInput{
		GatewayID: gatewayID,
		Name:      req.Name,
		Type:      domain.Type(req.Type),
		Enabled:   req.IsEnabled(),
		Config:    req.Config.ToDomain(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromAuth(a))
}
