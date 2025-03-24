package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type updateRuleHandler struct {
	logger                *logrus.Logger
	repo                  *database.Repository
	cache                 *cache.Cache
	validateRule          *rule.ValidateRule
	invalidationPublisher infraCache.EventPublisher
}

func NewUpdateRuleHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	validateRule *rule.ValidateRule,
	invalidationPublisher infraCache.EventPublisher,
) Handler {
	return &updateRuleHandler{
		logger:                logger,
		repo:                  repo,
		cache:                 cache,
		validateRule:          validateRule,
		invalidationPublisher: invalidationPublisher,
	}
}

// Handle @Summary Update a Rule
// @Description Updates an existing rule
// @Tags Rules
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param rule_id path string true "Rule ID"
// @Param rule body types.UpdateRuleRequest true "Updated rule data"
// @Success 204 "Rule updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Rule not found"
// @Router /api/v1/gateways/{gateway_id}/rules/{rule_id} [put]
func (s *updateRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	ruleID := c.Params("rule_id")

	var req types.UpdateRuleRequest
	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Convert UpdateRuleRequest to CreateRuleRequest for validation
	validateReq := types.CreateRuleRequest{
		Path:          req.Path,
		ServiceID:     req.ServiceID,
		Methods:       req.Methods,
		Headers:       req.Headers,
		StripPath:     req.StripPath,
		PreserveHost:  req.PreserveHost,
		RetryAttempts: req.RetryAttempts,
		PluginChain:   req.PluginChain,
	}

	// Validate the rule request
	if err := s.validateRule.Validate(&validateReq); err != nil {
		s.logger.WithError(err).Error("Rule validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Get existing rules from cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c.Context(), rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	// Find and update rule
	found := false
	for i, r := range rules {
		if r.ID == ruleID {
			if req.Path != "" {
				rules[i].Path = req.Path
			}
			if len(req.Methods) > 0 {
				rules[i].Methods = req.Methods
			}
			if req.Headers != nil {
				rules[i].Headers = s.convertMapToDBHeaders(req.Headers)
			}
			if req.StripPath != nil {
				rules[i].StripPath = *req.StripPath
			}
			if req.Active != nil {
				rules[i].Active = *req.Active
			}
			if req.PreserveHost != nil {
				rules[i].PreserveHost = *req.PreserveHost
			}
			if req.RetryAttempts != nil {
				rules[i].RetryAttempts = *req.RetryAttempts
			}
			if req.PluginChain != nil {
				chainJSON, err := json.Marshal(req.PluginChain)
				if err != nil {
					s.logger.WithError(err).Error("Failed to marshal plugin chain")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process plugin chain"})
				}
				var pluginChain []types.PluginConfig
				if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
					s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process plugin chain"})
				}
				rules[i].PluginChain = pluginChain
			}
			found = true
			break
		}
	}

	if !found {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Rule not found"})
	}

	// Save updated rules in cache
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	if err := s.cache.Set(c.Context(), rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	// Invalidate cache after updating the rule
	if err := s.invalidationPublisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{
			GatewayID: gatewayID,
		},
	); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (s *updateRuleHandler) convertMapToDBHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v
	}
	return result
}
