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
// @Description Updates only the plugin chain for a given gateway or rule
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

	// Validate plugin chain if provided
	if len(req.PluginChain) > 0 {
		// We need the gatewayID for validation context. For gateway type, it's req.ID.
		// For rule type, fetch the rule to obtain its GatewayID.
		switch req.Type {
		case "gateway":
			gatewayUUID, err := uuid.Parse(req.ID)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
			}
			if err := h.pluginChainValidator.Validate(c.Context(), gatewayUUID, req.PluginChain); err != nil {
				h.logger.WithError(err).Error("failed to validate plugin chain")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
			}
		case "rule":
			ruleUUID, err := uuid.Parse(req.ID)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule ID"})
			}
			rule, err := h.ruleRepo.GetRuleByID(c.Context(), ruleUUID)
			if err != nil {
				h.logger.WithError(err).Error("failed to fetch rule")
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
			}
			if err := h.pluginChainValidator.Validate(c.Context(), rule.GatewayID, req.PluginChain); err != nil {
				h.logger.WithError(err).Error("failed to validate plugin chain")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
			}
		}
	}

	switch req.Type {
	case "gateway":
		gatewayUUID, err := uuid.Parse(req.ID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
		}
		entity, err := h.gatewayRepo.Get(c.Context(), gatewayUUID)
		if err != nil || entity == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
		}
		// Overwrite required plugins with provided chain
		entity.RequiredPlugins = req.PluginChain
		entity.UpdatedAt = time.Now()
		if err := h.gatewayRepo.Update(c.Context(), entity); err != nil {
			h.logger.WithError(err).Error("failed to update gateway plugins")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update gateway"})
		}
		// Invalidate gateway cache
		if err := h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateGatewayCacheEvent{GatewayID: entity.ID.String()}); err != nil {
			h.logger.WithError(err).Error("failed to publish gateway cache update event")
		}
		return c.SendStatus(fiber.StatusNoContent)

	case "rule":
		ruleUUID, err := uuid.Parse(req.ID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule ID"})
		}
		rule, err := h.ruleRepo.GetRuleByID(c.Context(), ruleUUID)
		if err != nil || rule == nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
		}
		rule.PluginChain = req.PluginChain
		rule.UpdatedAt = time.Now()
		if err := h.ruleRepo.Update(c.Context(), rule); err != nil {
			h.logger.WithError(err).Error("failed to update rule plugins")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
		}
		// Invalidate rules cache for the gateway
		if err := h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.DeleteRulesCacheEvent{
			GatewayID: rule.GatewayID.String(),
		}); err != nil {
			h.logger.WithError(err).Error("failed to publish rules cache invalidation event")
		}
		return c.SendStatus(fiber.StatusNoContent)
	}

	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid type"})
}
