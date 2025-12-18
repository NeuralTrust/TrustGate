package http

import (
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

type deletePluginsHandler struct {
	logger               *logrus.Logger
	gatewayRepo          domainGateway.Repository
	ruleRepo             forwarding_rule.Repository
	pluginChainValidator appPlugin.ValidatePluginChain
	publisher            infraCache.EventPublisher
}

func NewDeletePluginsHandler(
	logger *logrus.Logger,
	gatewayRepo domainGateway.Repository,
	ruleRepo forwarding_rule.Repository,
	pluginChainValidator appPlugin.ValidatePluginChain,
	publisher infraCache.EventPublisher,
) Handler {
	return &deletePluginsHandler{
		logger:               logger,
		gatewayRepo:          gatewayRepo,
		ruleRepo:             ruleRepo,
		pluginChainValidator: pluginChainValidator,
		publisher:            publisher,
	}
}

// Handle @Summary Delete plugins from a Gateway or Rule
// @Description Deletes the specified plugins from a gateway's required plugins or a rule's plugin chain
// @Tags Plugins
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param payload body request.DeletePluginsRequest true "Delete plugins payload"
// @Success 204 "Plugins deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Entity not found"
// @Router /api/v1/plugins [delete]
func (h *deletePluginsHandler) Handle(c *fiber.Ctx) error {
	var req request.DeletePluginsRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	switch req.Type {
	case "gateway":
		return h.handleGatewayDelete(c, &req)
	case "rule":
		return h.handleRuleDelete(c, &req)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid type"})
	}
}

func (h *deletePluginsHandler) handleGatewayDelete(c *fiber.Ctx, req *request.DeletePluginsRequest) error {
	gatewayUUID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	entity, err := h.gatewayRepo.Get(c.Context(), gatewayUUID)
	if err != nil || entity == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	updated := filterOutPlugins(entity.RequiredPlugins, req.PluginIds)

	if err := h.pluginChainValidator.Validate(c.Context(), gatewayUUID, updated); err != nil {
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

func (h *deletePluginsHandler) handleRuleDelete(c *fiber.Ctx, req *request.DeletePluginsRequest) error {
	ruleUUID, err := uuid.Parse(req.ID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule ID"})
	}

	rule, err := h.ruleRepo.GetRuleByID(c.Context(), ruleUUID)
	if err != nil || rule == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	updated := filterOutPlugins(rule.PluginChain, req.PluginIds)

	// Validate with gateway context
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

	if err := h.publisher.Publish(
		c.Context(),
		event.DeleteRulesCacheEvent{GatewayID: rule.GatewayID.String()},
	); err != nil {
		h.logger.WithError(err).Error("failed to publish rules cache invalidation event")
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func filterOutPlugins(current []types.PluginConfig, toDelete []string) []types.PluginConfig {
	if len(current) == 0 || len(toDelete) == 0 {
		return current
	}
	// Build set for faster lookup
	set := make(map[string]struct{}, len(toDelete))
	for _, id := range toDelete {
		set[id] = struct{}{}
	}

	res := make([]types.PluginConfig, 0, len(current))
	for _, p := range current {
		if _, ok := set[p.ID]; !ok {
			res = append(res, p)
		}
	}
	return res
}
