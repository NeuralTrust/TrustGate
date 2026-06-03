package registry

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateRegistryHandler struct {
	updater appregistry.Updater
}

func NewUpdateRegistryHandler(updater appregistry.Updater) *UpdateRegistryHandler {
	return &UpdateRegistryHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a backend
// @Description  Updates an existing registry.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                        true  "Gateway id"  format(uuid)
// @Param        id          path      string                        true  "Registry id"  format(uuid)
// @Param        body        body      request.UpdateRegistryRequest  true  "Registry fields to update"
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id} [put]
func (h *UpdateRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateRegistryRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	b, err := h.updater.Update(c.UserContext(), appregistry.UpdateInput{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Provider:        req.Provider,
		ProviderOptions: req.ProviderOptions,
		Description:     req.Description,
		Weight:          req.Weight,
		Auth:            req.ToAuth(),
		HealthChecks:    req.ToHealthChecks(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromRegistry(b))
}
