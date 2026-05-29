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

type CreatePolicyHandler struct {
	creator apppolicy.Creator
}

func NewCreatePolicyHandler(creator apppolicy.Creator) *CreatePolicyHandler {
	return &CreatePolicyHandler{creator: creator}
}

func (h *CreatePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreatePolicyRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	p, err := h.creator.Create(c.UserContext(), apppolicy.CreateInput{
		GatewayID: gatewayID,
		Name:      req.Name,
		Plugins:   req.ToPlugins(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromPolicy(p))
}
