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
	creator    appgateway.Creator
	baseDomain string
}

func NewCreateGatewayHandler(creator appgateway.Creator, baseDomain string) *CreateGatewayHandler {
	return &CreateGatewayHandler{creator: creator, baseDomain: baseDomain}
}

// Handle godoc
// @Summary      Create a gateway
// @Description  Creates a new gateway.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway  body      request.CreateGatewayRequest  true  "Gateway to create"
// @Success      201      {object}  response.GatewayResponse
// @Failure      400      {object}  helpers.ErrorBody
// @Failure      401      {object}  helpers.ErrorBody
// @Failure      409      {object}  helpers.ErrorBody
// @Router       /v1/gateways [post]
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
		Slug:            req.Slug,
		Domain:          req.Domain,
		Metadata:        req.Metadata,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromDomain(g, h.baseDomain))
}
