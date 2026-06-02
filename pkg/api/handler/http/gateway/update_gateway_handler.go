package gateway

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateGatewayHandler struct {
	updater appgateway.Updater
}

func NewUpdateGatewayHandler(updater appgateway.Updater) *UpdateGatewayHandler {
	return &UpdateGatewayHandler{updater: updater}
}

func (h *UpdateGatewayHandler) Handle(c *fiber.Ctx) error {
	id, err := helpers.ParseUUIDParam[ids.GatewayKind](c, "id")
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	g, err := h.updater.Update(c.UserContext(), appgateway.UpdateInput{
		ID:              id,
		Name:            req.Name,
		Status:          req.Status,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromDomain(g))
}
