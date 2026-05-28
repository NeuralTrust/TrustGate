package policy

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
)

type ListPolicyHandler struct {
	finder apppolicy.Finder
}

func NewListPolicyHandler(finder apppolicy.Finder) *ListPolicyHandler {
	return &ListPolicyHandler{finder: finder}
}

func (h *ListPolicyHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseUUIDParam(c, "gateway_id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	page, err := helpers.ParsePage(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	size, err := helpers.ParseSize(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	req := request.ListPolicyRequest{
		Name: c.Query("name"),
		Page: page,
		Size: size,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID:    gatewayID,
		NameContains: req.Name,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}

	out := response.ListPolicyResponse{
		Items: make([]response.PolicyResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, p := range items {
		out.Items = append(out.Items, response.FromPolicy(p))
	}
	return helpers.WriteOK(c, out)
}
