package http

import (
	"fmt"
	"time"

	appPlugin "github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updatePluginsHandler struct {
	logger               *logrus.Logger
	gatewayRepo          domainGateway.Repository
	ruleRepo             forwarding_rule.Repository
	pluginChainValidator appPlugin.ValidatePluginChain
	publisher            infraCache.EventPublisher
}

func NewUpdatePluginsHandler(
	logger *logrus.Logger,
	gatewayRepo domainGateway.Repository,
	ruleRepo forwarding_rule.Repository,
	pluginChainValidator appPlugin.ValidatePluginChain,
	publisher infraCache.EventPublisher,
) Handler {
	return &updatePluginsHandler{
		logger:               logger,
		gatewayRepo:          gatewayRepo,
		ruleRepo:             ruleRepo,
		pluginChainValidator: pluginChainValidator,
		publisher:            publisher,
	}
}

// Handle @Summary Update plugins in a Gateway or Rule
// @Description Replaces plugins matched by ID within the chain, preserving the original id and name.
// @Tags Plugins
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param payload body request.UpdatePluginsRequest true "Update plugins payload"
// @Success 204 "Plugins updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Entity or plugin not found"
// @Router /api/v1/plugins [put]
func (h *updatePluginsHandler) Handle(c *fiber.Ctx) error {
	var req request.UpdatePluginsRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	switch req.Type {
	case "gateway":
		return h.handleGatewayUpdate(c, &req)
	case "rule":
		return h.handleRuleUpdate(c, &req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid type"})
	}
}

func (h *updatePluginsHandler) handleGatewayUpdate(c *fiber.Ctx, req *request.UpdatePluginsRequest) error {
	gID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	entity, err := h.gatewayRepo.Get(c.Context(), gID)
	if err != nil || entity == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	updated := make([]types.PluginConfig, len(entity.RequiredPlugins))
	copy(updated, entity.RequiredPlugins)

	for i, existing := range entity.RequiredPlugins {
		_ = i
		// Look for a payload plugin with same ID
		incoming, found := findIncomingByID(req.Plugins, existing.ID)
		if !found {
			continue
		}

		newCfg, err := buildPluginConfigFromMap(incoming, &existing)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid plugin payload for id %s: %v", existing.ID, err)})
		}

		updated[i] = newCfg
	}

	// Ensure all provided plugin IDs were matched
	for _, p := range req.Plugins {
		id := stringFromMap(p, "id")
		if !containsPluginID(entity.RequiredPlugins, id) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
		}
	}

	if err := h.pluginChainValidator.Validate(c.Context(), gID, updated); err != nil {
		h.logger.WithError(err).Error("failed to validate updated plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	entity.RequiredPlugins = updated
	entity.UpdatedAt = time.Now()
	if err := h.gatewayRepo.Update(c.Context(), entity); err != nil {
		h.logger.WithError(err).Error("failed to update gateway plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update gateway"})
	}

	if err := h.publisher.Publish(
		c.Context(),
		event.UpdateGatewayCacheEvent{GatewayID: entity.ID.String()},
	); err != nil {
		h.logger.WithError(err).Error("failed to publish gateway cache update event")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *updatePluginsHandler) handleRuleUpdate(c *fiber.Ctx, req *request.UpdatePluginsRequest) error {
	rID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule ID"})
	}

	rule, err := h.ruleRepo.GetRuleByID(c.Context(), rID)
	if err != nil || rule == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	updated := make([]types.PluginConfig, len(rule.PluginChain))
	copy(updated, rule.PluginChain)

	for i, existing := range rule.PluginChain {
		incoming, found := findIncomingByID(req.Plugins, existing.ID)
		if !found {
			continue
		}
		newCfg, err := buildPluginConfigFromMap(incoming, &existing)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid plugin payload for id %s: %v", existing.ID, err)})
		}
		updated[i] = newCfg
	}

	for _, p := range req.Plugins {
		id := stringFromMap(p, "id")
		if !containsPluginID(rule.PluginChain, id) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "plugin not found"})
		}
	}

	if err := h.pluginChainValidator.Validate(c.Context(), rule.GatewayID, updated); err != nil {
		h.logger.WithError(err).Error("failed to validate updated plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	rule.PluginChain = updated
	rule.UpdatedAt = time.Now()
	if err := h.ruleRepo.Update(c.Context(), rule); err != nil {
		h.logger.WithError(err).Error("failed to update rule plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
	}

	// Refresh rules cache synchronously to avoid stale reads after update
	if _, err := h.ruleRepo.ListRules(c.Context(), rule.GatewayID); err != nil {
		h.logger.WithError(err).Warn("failed to refresh rules cache after plugin update")
	}

	if err := h.publisher.Publish(
		c.Context(),
		event.DeleteRulesCacheEvent{GatewayID: rule.GatewayID.String()},
	); err != nil {
		h.logger.WithError(err).Error("failed to publish rules cache invalidation event")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func findIncomingByID(list []map[string]any, id string) (map[string]any, bool) {
	for _, m := range list {
		if stringFromMap(m, "id") == id {
			return m, true
		}
	}
	return nil, false
}

func containsPluginID(list []types.PluginConfig, id string) bool {
	for _, p := range list {
		if p.ID == id {
			return true
		}
	}
	return false
}

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func boolFromMap(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func intFromMap(m map[string]any, key string, def int) int {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	default:
		return def
	}
}

func stageFromMap(m map[string]any, key string, def types.Stage) types.Stage {
	s := stringFromMap(m, key)
	if s == "" {
		return def
	}
	return types.Stage(s)
}

func settingsFromMap(m map[string]any, key string, def map[string]any) map[string]any {
	v, ok := m[key]
	if !ok {
		return def
	}
	if mm, ok := v.(map[string]any); ok {
		return mm
	}
	return def
}

// buildPluginConfigFromMap builds a new PluginConfig using incoming fields but preserving
// ID and Name from the existing plugin.
func buildPluginConfigFromMap(in map[string]any, existing *types.PluginConfig) (types.PluginConfig, error) {
	cfg := types.PluginConfig{}
	cfg.ID = existing.ID
	cfg.Name = existing.Name
	cfg.Enabled = boolFromMap(in, "enabled", existing.Enabled)
	cfg.Stage = stageFromMap(in, "stage", existing.Stage)
	cfg.Priority = intFromMap(in, "priority", existing.Priority)
	cfg.Parallel = boolFromMap(in, "parallel", existing.Parallel)
	cfg.Settings = settingsFromMap(in, "settings", existing.Settings)
	return cfg, nil
}
