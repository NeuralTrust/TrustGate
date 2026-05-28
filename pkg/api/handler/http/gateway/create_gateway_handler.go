package gateway

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type CreateGatewayHandler struct {
	creator appgateway.Creator
}

func NewCreateGatewayHandler(creator appgateway.Creator) *CreateGatewayHandler {
	return &CreateGatewayHandler{creator: creator}
}

func (h *CreateGatewayHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	g, err := h.creator.Create(c.UserContext(), appgateway.CreateInput{
		Name:            req.Name,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromDomain(g))
}
