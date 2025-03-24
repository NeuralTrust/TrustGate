package http

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type listRulesHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewListRulesHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &listRulesHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

// Handle @Summary Retrieve all Rules
// @Description Returns a list of all rules for a gateway
// @Tags Rules
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success 200 {array} forwarding_rule.ForwardingRule "List of rules"
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/gateways/{gateway_id}/rules [get]
func (s *listRulesHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	// Get rules from database
	dbRules, err := s.repo.ListRules(c.Context(), gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to list rules"})
	}

	// Convert to API response format
	rules := make([]types.ForwardingRule, len(dbRules))
	for i, rule := range dbRules {
		rules[i] = types.ForwardingRule{
			ID:            rule.ID,
			GatewayID:     rule.GatewayID,
			Path:          rule.Path,
			ServiceID:     rule.ServiceID,
			Methods:       rule.Methods,
			Headers:       rule.Headers,
			StripPath:     rule.StripPath,
			PreserveHost:  rule.PreserveHost,
			RetryAttempts: rule.RetryAttempts,
			PluginChain:   rule.PluginChain,
			Active:        rule.Active,
			Public:        rule.Public,
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}
	}

	// Cache the rules for future requests
	rulesJSON, err := json.Marshal(rules)
	if err == nil {
		rulesKey := fmt.Sprintf("rules:%s", gatewayID)
		if err := s.cache.Set(c.Context(), rulesKey, string(rulesJSON), 0); err != nil {
			s.logger.WithError(err).Warn("Failed to cache rules")
		}
	}

	return c.Status(fiber.StatusOK).JSON(rules)
}
