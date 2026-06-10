package role

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role/response"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/gofiber/fiber/v2"
)

type ListRoleHandler struct {
	finder approle.Finder
}

func NewListRoleHandler(finder approle.Finder) *ListRoleHandler {
	return &ListRoleHandler{finder: finder}
}

func (h *ListRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
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
	req := request.ListRoleRequest{
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
	out := response.ListRoleResponse{
		Items: make([]response.RoleResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, role := range items {
		out.Items = append(out.Items, response.FromRole(role))
	}
	return helpers.WriteOK(c, out)
}
