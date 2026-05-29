package policy

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type UpdatePolicyHandler struct {
	updater apppolicy.Updater
}

func NewUpdatePolicyHandler(updater apppolicy.Updater) *UpdatePolicyHandler {
	return &UpdatePolicyHandler{updater: updater}
}

func (h *UpdatePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdatePolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	p, err := h.updater.Update(c.UserContext(), apppolicy.UpdateInput{
		ID:        id,
		GatewayID: gatewayID,
		Name:      req.Name,
		Plugins:   req.ToPlugins(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromPolicy(p))
}
