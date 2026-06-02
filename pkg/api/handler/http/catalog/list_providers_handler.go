package catalog

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	"github.com/gofiber/fiber/v2"
)

type ListProvidersHandler struct {
	service appcatalog.Service
}

func NewListProvidersHandler(service appcatalog.Service) *ListProvidersHandler {
	return &ListProvidersHandler{service: service}
}

func (h *ListProvidersHandler) Handle(c *fiber.Ctx) error {
	providers, err := h.service.ListProviders(c.UserContext())
	if err != nil {
		return helpers.WriteError(c, err)
	}
	out := make([]response.ProviderResponse, 0, len(providers))
	for _, p := range providers {
		out = append(out, response.FromProvider(p))
	}
	return helpers.WriteOK(c, fiber.Map{"items": out})
}
