package registry

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type CreateRegistryHandler struct {
	creator appregistry.Creator
}

func NewCreateRegistryHandler(creator appregistry.Creator) *CreateRegistryHandler {
	return &CreateRegistryHandler{creator: creator}
}

// Handle godoc
// @Summary      Create a backend
// @Description  Creates a new backend in a gateway.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                        true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateRegistryRequest  true  "Registry to create"
// @Success      201         {object}  response.RegistryResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries [post]
func (h *CreateRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreateRegistryRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	b, err := h.creator.Create(c.UserContext(), appregistry.CreateInput{
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
	return helpers.WriteCreated(c, response.FromRegistry(b))
}
