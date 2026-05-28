package backend

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/response"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type UpdateBackendHandler struct {
	updater appbackend.Updater
}

func NewUpdateBackendHandler(updater appbackend.Updater) *UpdateBackendHandler {
	return &UpdateBackendHandler{updater: updater}
}

func (h *UpdateBackendHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseUUIDParam(c, "gateway_id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	id, err := helpers.ParseUUIDParam(c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateBackendRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	b, err := h.updater.Update(c.UserContext(), appbackend.UpdateInput{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Algorithm:       req.Algorithm,
		Targets:         req.ToTargets(),
		EmbeddingConfig: req.ToEmbeddingConfig(),
		HealthChecks:    req.ToHealthChecks(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromBackend(b))
}
