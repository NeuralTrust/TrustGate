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

type CreateBackendHandler struct {
	creator appbackend.Creator
}

func NewCreateBackendHandler(creator appbackend.Creator) *CreateBackendHandler {
	return &CreateBackendHandler{creator: creator}
}

func (h *CreateBackendHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseUUIDParam(c, "gateway_id")
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreateBackendRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	b, err := h.creator.Create(c.UserContext(), appbackend.CreateInput{
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
	return helpers.WriteCreated(c, response.FromBackend(b))
}
