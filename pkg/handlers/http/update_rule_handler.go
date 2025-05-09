package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domainTypes "github.com/NeuralTrust/TrustGate/pkg/domain"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateRuleHandler struct {
	logger                *logrus.Logger
	repo                  *database.Repository
	cache                 *cache.Cache
	validatePlugin        *plugin.ValidatePlugin
	invalidationPublisher infraCache.EventPublisher
}

func NewUpdateRuleHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	validatePlugin *plugin.ValidatePlugin,
	invalidationPublisher infraCache.EventPublisher,
) Handler {
	return &updateRuleHandler{
		logger:                logger,
		repo:                  repo,
		cache:                 cache,
		validatePlugin:        validatePlugin,
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
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	// Validate the rule request
	if err := s.validate(&req); err != nil {
		s.logger.WithError(err).Error("Rule validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}
	ruleUUID, err := uuid.Parse(ruleID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule_id"})
	}

	err = s.updateForwardingRuleDB(c.Context(), ruleUUID, gatewayUUID, req)
	if err != nil {
		if errors.As(err, &domain.ErrEntityNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
		}
		s.logger.WithError(err).Error("Failed to update rule in database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
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
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	// Save updated rules in cache
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
	}

	if err := s.cache.Set(c.Context(), rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update rule"})
	}

	// Invalidate cache after updating the rule
	if err := s.invalidationPublisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{
			GatewayID: gatewayID,
		},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish cache invalidation")
	}

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (s *updateRuleHandler) updateForwardingRuleDB(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
	req types.UpdateRuleRequest,
) error {
	forwardingRule, err := s.repo.GetRule(ctx, ruleUUID, gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rule")
		return fmt.Errorf("failed to get rule: %w", err)
	}

	if forwardingRule == nil {
		return domain.NewNotFoundError("rule", ruleUUID)
	}

	serviceUUID, err := uuid.Parse(req.ServiceID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse service ID")
		return fmt.Errorf("invalid service ID: %w", err)
	}

	forwardingRule.Path = req.Path
	forwardingRule.ServiceID = serviceUUID
	forwardingRule.Methods = req.Methods
	forwardingRule.Headers = req.Headers

	if req.StripPath != nil {
		forwardingRule.StripPath = *req.StripPath
	}
	if req.PreserveHost != nil {
		forwardingRule.PreserveHost = *req.PreserveHost
	}
	if req.RetryAttempts != nil {
		forwardingRule.RetryAttempts = *req.RetryAttempts
	}
	if req.Active != nil {
		forwardingRule.Active = *req.Active
	}

	var trustLensConfig *domainTypes.TrustLensJSON
	if req.TrustLens != nil {
		trustLensConfig = &domainTypes.TrustLensJSON{
			AppID:  req.TrustLens.AppID,
			TeamID: req.TrustLens.TeamID,
		}
		forwardingRule.TrustLens = trustLensConfig
	}

	forwardingRule.PluginChain = req.PluginChain
	forwardingRule.UpdatedAt = time.Now()

	if err := s.repo.UpdateRule(ctx, forwardingRule); err != nil {
		s.logger.WithError(err).Error("failed to update rule")
		return fmt.Errorf("failed to update rule: %w", err)
	}

	return nil
}

func (s *updateRuleHandler) convertMapToDBHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v
	}
	return result
}

func (s *updateRuleHandler) validate(rule *types.UpdateRuleRequest) error {

	if rule.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(rule.Methods) == 0 {
		return fmt.Errorf("at least one method is required")
	}

	if rule.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}

	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	for _, method := range rule.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	if len(rule.PluginChain) > 0 {
		for i, pl := range rule.PluginChain {
			if err := s.validatePlugin.Validate(pl); err != nil {
				return fmt.Errorf("plugin %d: %v", i, err)
			}
		}
	}

	if rule.TrustLens != nil {
		if rule.TrustLens.AppID == "" {
			return fmt.Errorf("trust lens app id is required")
		}
		if rule.TrustLens.TeamID == "" {
			return fmt.Errorf("trust lens team id is required")
		}
	}

	return nil
}
