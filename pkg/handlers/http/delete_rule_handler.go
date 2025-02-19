package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteRuleHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	cache     *cache.Cache
	publisher infraCache.InvalidationPublisher
}

func NewDeleteRuleHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	publisher infraCache.InvalidationPublisher,
) Handler {
	return &deleteRuleHandler{
		logger:    logger,
		repo:      repo,
		cache:     cache,
		publisher: publisher,
	}
}

func (s *deleteRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	ruleID := c.Params("rule_id")

	// Get existing rules from cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c.Context(), rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete rule"})
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete rule"})
	}

	// Find and remove rule
	found := false
	var updatedRules []types.ForwardingRule
	for _, rule := range rules {
		if rule.ID == ruleID {
			found = true
			continue
		}
		updatedRules = append(updatedRules, rule)
	}

	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Rule not found"})
	}

	// Save updated rules in cache
	updatedJSON, err := json.Marshal(updatedRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete rule"})
	}

	if err := s.cache.Set(c.Context(), rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete rule"})
	}

	// Invalidate cache after deletion
	if err := s.publisher.Publish(c.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Rule deleted successfully"})
}
