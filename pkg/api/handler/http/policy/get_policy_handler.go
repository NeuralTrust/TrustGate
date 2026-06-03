package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type GetPolicyHandler struct {
	finder apppolicy.Finder
}

func NewGetPolicyHandler(finder apppolicy.Finder) *GetPolicyHandler {
	return &GetPolicyHandler{finder: finder}
}

// Handle godoc
// @Summary      Get a policy
// @Description  Returns a single policy by id.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        id          path      string  true  "Policy id"   format(uuid)
// @Success      200         {object}  response.PolicyResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id} [get]
func (h *GetPolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	p, err := h.finder.FindByID(c.UserContext(), gatewayID, id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromPolicy(p))
}
