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

// Handle godoc
// @Summary      Update a gateway
// @Description  Updates an existing gateway.
// @Tags         gateways
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                        true  "Gateway id"  format(uuid)
// @Param        gateway  body      request.UpdateGatewayRequest  true  "Gateway fields to update"
// @Success      200      {object}  response.GatewayResponse
// @Failure      400      {object}  helpers.ErrorBody
// @Failure      401      {object}  helpers.ErrorBody
// @Failure      404      {object}  helpers.ErrorBody
// @Failure      409      {object}  helpers.ErrorBody
// @Router       /v1/gateways/{id} [put]
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
		Slug:            req.Slug,
		Status:          req.Status,
		Domain:          req.Domain,
		Telemetry:       req.Telemetry,
		ClientTLSConfig: req.ClientTLSConfig,
		SessionConfig:   req.SessionConfig,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromDomain(g))
}
