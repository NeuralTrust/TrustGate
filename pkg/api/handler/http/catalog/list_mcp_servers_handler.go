package catalog

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	"github.com/gofiber/fiber/v2"
)

type ListMCPServersHandler struct {
	catalog appcatalog.MCPServerCatalog
}

func NewListMCPServersHandler(catalog appcatalog.MCPServerCatalog) *ListMCPServersHandler {
	return &ListMCPServersHandler{catalog: catalog}
}

type ListMCPServersResponse struct {
	MCPServers []domain.MCPServer `json:"mcp_servers"`
}

// Handle godoc
// @Summary      List the MCP servers catalog
// @Description  Returns the curated catalog of well-known remote MCP servers, used to prefill MCP registry creation.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  ListMCPServersResponse
// @Failure      401  {object}  helpers.ErrorBody
// @Router       /v1/mcp-servers-catalog [get]
func (h *ListMCPServersHandler) Handle(c *fiber.Ctx) error {
	return helpers.WriteOK(c, ListMCPServersResponse{MCPServers: h.catalog.ListMCPServers()})
}
