package http

import (
	"encoding/json"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type MCPToolsHandler struct {
	*BaseHandler
	mcpUpstreamService service.MCPUpstreamService
}

func NewMCPToolsHandler(
	logger *logrus.Logger,
	cache *cache.Cache,
	pluginManager plugins.Manager,
	cfg *config.Config,
	mcpUpstreamService service.MCPUpstreamService,
) Handler {
	return &MCPToolsHandler{
		BaseHandler:        NewBaseHandler(logger, cache, pluginManager, cfg),
		mcpUpstreamService: mcpUpstreamService,
	}
}

func (h *MCPToolsHandler) Handle(c *fiber.Ctx) error {
	startTime := time.Now()

	reqCtx, respCtx, metricsCollector, gatewayID, err := h.PrepareRequestContext(c)
	if err != nil {
		h.logger.WithError(err).Error("Failed to prepare request context")
		return h.HandleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Internal server error"})
	}

	if err := h.ExecutePreRequestStage(c.Context(), gatewayID, reqCtx, respCtx, metricsCollector, c); err != nil {
		return err
	}

	if respCtx.StopProcessing {
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}
		return h.HandleSuccessResponse(c, respCtx.StatusCode, respCtx.Body)
	}

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		h.logger.WithError(err).Error("Invalid gateway ID")
		return h.HandleErrorResponse(c, fiber.StatusBadRequest, fiber.Map{"error": "Invalid gateway ID"})
	}

	mcpUpstreams, err := h.mcpUpstreamService.List(c.Context(), gatewayUUID, 0, 100)
	if err != nil {
		h.logger.WithError(err).Error("Failed to fetch MCP upstreams")
		return h.HandleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Failed to fetch MCP tools"})
	}

	var allTools []map[string]interface{}
	for _, mcpUpstream := range mcpUpstreams {
		tools := mcpUpstream.ListAllTools()
		for _, tool := range tools {
			toolMap := map[string]interface{}{
				"name":        tool.Name,
				"description": tool.Description,
				"schema":      tool.Schema,
				"server_id":   tool.ServerID,
				"upstream_id": mcpUpstream.ID.String(),
			}
			allTools = append(allTools, toolMap)
		}
	}

	response := fiber.Map{
		"tools": allTools,
		"count": len(allTools),
	}

	respCtx.StatusCode = fiber.StatusOK
	respBody, _ := json.Marshal(response)
	respCtx.Body = respBody

	if err := h.ExecutePreResponseStage(c.Context(), gatewayID, reqCtx, respCtx, metricsCollector, c); err != nil {
		return err
	}

	if err := h.ExecutePostResponseStage(c.Context(), gatewayID, reqCtx, respCtx, metricsCollector, c); err != nil {
		return err
	}

	for k, values := range respCtx.Headers {
		for _, v := range values {
			c.Set(k, v)
		}
	}

	duration := time.Since(startTime).Milliseconds()
	h.RecordPrometheusMetrics(gatewayID, "mcp-tools", "tools", duration)

	h.RegistrySuccessEvent(metricsCollector, respCtx)

	return h.HandleSuccessJSONResponse(c, respCtx.StatusCode, response)
}
