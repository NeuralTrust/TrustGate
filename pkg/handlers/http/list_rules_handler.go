package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway uuid"})
	}
	// Get rules from database
	_, err = s.repo.GetGateway(c.Context(), gatewayUUID)
	
	if err != nil {
		if errors.As(err, &domain.ErrEntityNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
		}
		s.logger.WithError(err).Error("failed to get gateway from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get gateway"})
	}

	dbRules, err := s.repo.ListRules(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rules from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list rules"})
	}

	// Convert to API response format
	rules := make([]types.ForwardingRule, len(dbRules))
	for i, rule := range dbRules {
		rules[i] = types.ForwardingRule{
			ID:            rule.ID.String(),
			GatewayID:     rule.GatewayID.String(),
			Path:          rule.Path,
			ServiceID:     rule.ServiceID.String(),
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
			s.logger.WithError(err).Warn("failed to cache rules")
		}
	}

	return c.Status(fiber.StatusOK).JSON(rules)
}
