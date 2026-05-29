package auth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

type ListAuthHandler struct {
	finder appauth.Finder
}

func NewListAuthHandler(finder appauth.Finder) *ListAuthHandler {
	return &ListAuthHandler{finder: finder}
}

func (h *ListAuthHandler) Handle(c *fiber.Ctx) error {
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
	req := request.ListAuthRequest{
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

	out := response.ListAuthResponse{
		Items: make([]response.AuthResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, a := range items {
		out.Items = append(out.Items, response.FromAuth(a))
	}
	return helpers.WriteOK(c, out)
}
