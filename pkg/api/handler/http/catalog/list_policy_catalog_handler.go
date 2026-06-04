package catalog

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/gofiber/fiber/v2"
)

type ListPolicyCatalogHandler struct {
	service appplugins.CatalogService
}

func NewListPolicyCatalogHandler(service appplugins.CatalogService) *ListPolicyCatalogHandler {
	return &ListPolicyCatalogHandler{service: service}
}

// Handle godoc
// @Summary      List policy catalog
// @Description  Returns the catalog of available policies grouped by type. Each entry includes the settings schema needed to render its configuration form dynamically.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  appplugins.Catalog
// @Failure      401  {object}  helpers.ErrorBody
// @Router       /v1/policies-catalog [get]
func (h *ListPolicyCatalogHandler) Handle(c *fiber.Ctx) error {
	return helpers.WriteOK(c, h.service.Catalog())
}
