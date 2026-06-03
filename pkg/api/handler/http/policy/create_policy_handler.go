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

// Handle godoc
// @Summary      Create a policy
// @Description  Creates a new policy in a gateway.
// @Tags         policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                       true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreatePolicyRequest  true  "Policy to create"
// @Success      201         {object}  response.PolicyResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies [post]
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
		Slug:      req.Slug,
		Enabled:   req.Enabled,
		Priority:  req.Priority,
		Parallel:  req.Parallel,
		Settings:  req.Settings,
		Stages:    req.ToStages(),
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromPolicy(p))
}
