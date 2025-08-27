package http

import (
	"time"

	appPlugin "github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
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

// Handle @Summary Update plugins for a Gateway or Rule
// @Description Updates the plugin chain for a given gateway or rule with granular add/edit/delete operations
// @Tags Plugins
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param payload body request.UpdatePluginsRequest true "Update plugins payload"
// @Success 204 "Plugins updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Entity not found"
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

	// Handle granular updates based on type
	switch req.Type {
	case "gateway":
		return h.handleGatewayUpdates(c, &req)
	case "rule":
		return h.handleRuleUpdates(c, &req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid type"})
	}
}

func (h *updatePluginsHandler) handleGatewayUpdates(c *fiber.Ctx, req *request.UpdatePluginsRequest) error {
	gatewayUUID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	entity, err := h.gatewayRepo.Get(c.Context(), gatewayUUID)
	if err != nil || entity == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	// Apply updates to the plugin chain
	updatedPlugins, err := h.applyPluginUpdates(entity.RequiredPlugins, req.Updates)
	if err != nil {
		h.logger.WithError(err).Error("failed to apply plugin updates")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Validate the updated plugin chain
	if err := h.pluginChainValidator.Validate(c.Context(), gatewayUUID, updatedPlugins); err != nil {
		h.logger.WithError(err).Error("failed to validate updated plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Update the gateway
	entity.RequiredPlugins = updatedPlugins
	entity.UpdatedAt = time.Now()
	if err := h.gatewayRepo.Update(c.Context(), entity); err != nil {
		h.logger.WithError(err).Error("failed to update gateway plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update gateway"})
	}

	// Publish cache update event
	if err := h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateGatewayCacheEvent{GatewayID: entity.ID.String()}); err != nil {
		h.logger.WithError(err).Error("failed to publish gateway cache update event")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *updatePluginsHandler) handleRuleUpdates(c *fiber.Ctx, req *request.UpdatePluginsRequest) error {
	ruleUUID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule ID"})
	}

	rule, err := h.ruleRepo.GetRuleByID(c.Context(), ruleUUID)
	if err != nil || rule == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	// Apply updates to the plugin chain
	updatedPlugins, err := h.applyPluginUpdates(rule.PluginChain, req.Updates)
	if err != nil {
		h.logger.WithError(err).Error("failed to apply plugin updates")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Validate the updated plugin chain
	if err := h.pluginChainValidator.Validate(c.Context(), rule.GatewayID, updatedPlugins); err != nil {
		h.logger.WithError(err).Error("failed to validate updated plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Update the rule
	rule.PluginChain = updatedPlugins
	rule.UpdatedAt = time.Now()
	if err := h.ruleRepo.Update(c.Context(), rule); err != nil {
		h.logger.WithError(err).Error("failed to update rule plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
	}

	// Publish cache invalidation event
	if err := h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.DeleteRulesCacheEvent{
		GatewayID: rule.GatewayID.String(),
	}); err != nil {
		h.logger.WithError(err).Error("failed to publish rules cache invalidation event")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// applyPluginUpdates applies a series of plugin updates to an existing plugin chain
func (h *updatePluginsHandler) applyPluginUpdates(currentPlugins []types.PluginConfig, updates []request.PluginUpdate) ([]types.PluginConfig, error) {
	// Create a copy of the current plugins to avoid modifying the original
	result := make([]types.PluginConfig, len(currentPlugins))
	copy(result, currentPlugins)

	for _, update := range updates {
		switch update.Operation {
		case request.PluginOperationAdd:
			// Check if plugin with the same name already exists
			for _, p := range result {
				if p.Name == update.Plugin.Name {
					return nil, fiber.NewError(fiber.StatusBadRequest, "plugin '"+update.Plugin.Name+"' already exists")
				}
			}
			result = append(result, update.Plugin)

		case request.PluginOperationEdit:
			found := false
			targetName := update.OldPluginName
			if targetName == "" {
				targetName = update.Plugin.Name
			}

			for i, p := range result {
				if p.Name == targetName {
					// Preserve the ID if not provided in the update
					if update.Plugin.ID == "" {
						update.Plugin.ID = p.ID
					}
					result[i] = update.Plugin
					found = true
					break
				}
			}
			if !found {
				return nil, fiber.NewError(fiber.StatusNotFound, "plugin '"+targetName+"' not found")
			}

		case request.PluginOperationDelete:
			targetName := update.PluginName
			if targetName == "" {
				targetName = update.Plugin.Name
			}

			newResult := make([]types.PluginConfig, 0, len(result))
			found := false
			for _, p := range result {
				if p.Name != targetName {
					newResult = append(newResult, p)
				} else {
					found = true
				}
			}
			if !found {
				return nil, fiber.NewError(fiber.StatusNotFound, "plugin '"+targetName+"' not found")
			}
			result = newResult

		default:
			return nil, fiber.NewError(fiber.StatusBadRequest, "invalid operation: "+string(update.Operation))
		}
	}

	return result, nil
}
