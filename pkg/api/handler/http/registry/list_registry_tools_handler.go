package registry

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type ListRegistryToolsHandler struct {
	introspector appmcp.Introspector
}

func NewListRegistryToolsHandler(introspector appmcp.Introspector) *ListRegistryToolsHandler {
	return &ListRegistryToolsHandler{introspector: introspector}
}

type ListRegistryToolsResponse struct {
	Tools []appmcp.Tool `json:"tools"`
}

// Handle godoc
// @Summary      List the tools of an MCP registry
// @Description  Connects to the upstream MCP server and returns its discoverable tools, for building consumer toolkits.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  ListRegistryToolsResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      502         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/tools [get]
func (h *ListRegistryToolsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	tools, err := h.introspector.ListRegistryTools(c.UserContext(), gatewayID, id)
	if err != nil {
		if errors.Is(err, appmcp.ErrUpstreamUnavailable) {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}
		return helpers.WriteError(c, err)
	}
	if tools == nil {
		tools = []appmcp.Tool{}
	}
	return helpers.WriteOK(c, ListRegistryToolsResponse{Tools: tools})
}
