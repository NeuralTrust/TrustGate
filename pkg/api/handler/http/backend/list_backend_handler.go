package backend

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/gofiber/fiber/v2"
)

type ListBackendHandler struct {
	finder appbackend.Finder
}

func NewListBackendHandler(finder appbackend.Finder) *ListBackendHandler {
	return &ListBackendHandler{finder: finder}
}

func (h *ListBackendHandler) Handle(c *fiber.Ctx) error {
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
	req := request.ListBackendRequest{
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

	out := response.ListBackendResponse{
		Items: make([]response.BackendResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, b := range items {
		out.Items = append(out.Items, response.FromBackend(b))
	}
	return helpers.WriteOK(c, out)
}
