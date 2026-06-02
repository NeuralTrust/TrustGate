package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeletePolicyHandler struct {
	deleter apppolicy.Deleter
}

func NewDeletePolicyHandler(deleter apppolicy.Deleter) *DeletePolicyHandler {
	return &DeletePolicyHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete a policy
// @Description  Deletes a policy from a gateway.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        id          path  string  true  "Policy id"   format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/{id} [delete]
func (h *DeletePolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.PolicyKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}
