package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/gofiber/fiber/v2"
)

type GetPolicyHandler struct {
	finder apppolicy.Finder
}

func NewGetPolicyHandler(finder apppolicy.Finder) *GetPolicyHandler {
	return &GetPolicyHandler{finder: finder}
}

func (h *GetPolicyHandler) Handle(c *fiber.Ctx) error {
	_, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	p, err := h.finder.FindByID(c.UserContext(), id)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromPolicy(p))
}
