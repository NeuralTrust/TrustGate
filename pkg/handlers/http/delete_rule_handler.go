package http

import (
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type deleteRuleHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	cache     *cache.Cache
	publisher infraCache.EventPublisher
}

func NewDeleteRuleHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	publisher infraCache.EventPublisher,
) Handler {
	return &deleteRuleHandler{
		logger:    logger,
		repo:      repo,
		cache:     cache,
		publisher: publisher,
	}
}

// Handle @Summary Delete a Rule
// @Description Removes a rule from a gateway
// @Tags Rules
// @Param gateway_id path string true "Gateway ID"
// @Param rule_id path string true "Rule ID"
// @Success 204 "Rule deleted successfully"
// @Failure 404 {object} map[string]interface{} "Rule not found"
// @Router /api/v1/gateways/{gateway_id}/rules/{rule_id} [delete]
func (s *deleteRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	ruleID := c.Params("rule_id")
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}
	ruleUUID, err := uuid.Parse(c.Params("rule_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule_id"})
	}
	err = s.repo.DeleteRule(c.Context(), ruleUUID, gatewayUUID)
	if err != nil {
		if errors.Is(err, database.ErrRuleNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(
				fiber.Map{
					"error": fmt.Sprintf("rule not found with id %s and gateway %s", ruleID, gatewayID),
				},
			)
		}
		s.logger.WithError(err).Error("failed to delete rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete rule"})
	}

	// Invalidate cache after deletion
	if err := s.publisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteRulesCacheEvent{GatewayID: gatewayID, RuleID: ruleID},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish cache invalidation")
	}

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}
