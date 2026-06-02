package backend

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
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

// Handle godoc
// @Summary      Create a backend
// @Description  Creates a new backend in a gateway.
// @Tags         backends
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                        true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateBackendRequest  true  "Backend to create"
// @Success      201         {object}  response.BackendResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/backends [post]
func (h *CreateBackendHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
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
	return helpers.WriteCreated(c, response.FromBackend(b))
}
