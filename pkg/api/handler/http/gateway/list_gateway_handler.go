package gateway

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type ListGatewayHandler struct {
	finder appgateway.Finder
}

func NewListGatewayHandler(finder appgateway.Finder) *ListGatewayHandler {
	return &ListGatewayHandler{finder: finder}
}

func (h *ListGatewayHandler) Handle(c *fiber.Ctx) error {
	page, err := helpers.ParsePage(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	size, err := helpers.ParseSize(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	req := request.ListGatewayRequest{
		Name: c.Query("name"),
		Page: page,
		Size: size,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		NameContains: req.Name,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}

	out := response.ListGatewayResponse{
		Items: make([]response.GatewayResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, g := range items {
		out.Items = append(out.Items, response.FromDomain(g))
	}
	return helpers.WriteOK(c, out)
}
