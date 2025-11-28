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
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
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
	repo                  forwarding_rule.Repository
	cache                 cache.Cache
	validatePlugin        *plugin.ValidatePlugin
	invalidationPublisher infraCache.EventPublisher
}

func NewUpdateRuleHandler(
	logger *logrus.Logger,
	repo forwarding_rule.Repository,
	cache cache.Cache,
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
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param rule_id path string true "Rule ID"
// @Param rule body request.UpdateRuleRequest true "Updated rule data"
// @Success 204 "Rule updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Rule not found"
// @Router /api/v1/gateways/{gateway_id}/rules/{rule_id} [put]
func (s *updateRuleHandler) Handle(c *fiber.Ctx) error {
	updateReq, err := s.parseRequestBody(c)
	if err != nil {
		return err
	}

	if updateReq == nil {
		s.logger.Error("parsed request body is nil")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := s.validate(updateReq); err != nil {
		s.logger.WithError(err).Error("rule validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	gatewayID := c.Params("gateway_id")
	ruleID := c.Params("rule_id")

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}

	ruleUUID, err := uuid.Parse(ruleID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule_id"})
	}

	if err := s.updateForwardingRuleDB(c.Context(), ruleUUID, gatewayUUID, *updateReq); err != nil {
		return s.handleUpdateError(c, err)
	}

	if err := s.updateRuleInCache(c, gatewayID, ruleID, *updateReq); err != nil {
		return err
	}

	s.publishCacheInvalidation(c.Context(), gatewayID)

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (s *updateRuleHandler) updateForwardingRuleDB(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
	updateReq req.UpdateRuleRequest,
) error {
	forwardingRule, err := s.getRuleFromDB(ctx, ruleUUID, gatewayUUID)
	if err != nil {
		return err
	}

	serviceUUID, err := s.parseAndUpdateServiceID(forwardingRule, updateReq)
	if err != nil {
		return err
	}

	if err := s.validateRuleUniqueness(ctx, ruleUUID, gatewayUUID, updateReq, serviceUUID); err != nil {
		return err
	}

	s.applyRequestToDBRule(forwardingRule, updateReq)
	forwardingRule.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, forwardingRule); err != nil {
		s.logger.WithError(err).Error("failed to update rule")
		return fmt.Errorf("failed to update rule: %w", err)
	}

	return nil
}

func (s *updateRuleHandler) getRuleFromDB(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
) (*forwarding_rule.ForwardingRule, error) {
	forwardingRule, err := s.repo.GetRule(ctx, ruleUUID, gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rule")
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}

	if forwardingRule == nil {
		return nil, domain.NewNotFoundError("rule", ruleUUID)
	}

	return forwardingRule, nil
}

func (s *updateRuleHandler) parseAndUpdateServiceID(
	forwardingRule *forwarding_rule.ForwardingRule,
	updateReq req.UpdateRuleRequest,
) (uuid.UUID, error) {
	if updateReq.ServiceID == "" {
		return uuid.Nil, nil
	}

	serviceUUID, err := uuid.Parse(updateReq.ServiceID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse service ID")
		return uuid.Nil, fmt.Errorf("invalid service ID: %w", err)
	}

	forwardingRule.ServiceID = serviceUUID
	return serviceUUID, nil
}

func (s *updateRuleHandler) validateRuleUniqueness(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
	updateReq req.UpdateRuleRequest,
	serviceUUID uuid.UUID,
) error {
	if updateReq.Path == "" || serviceUUID == uuid.Nil {
		return nil
	}

	rules, err := s.repo.ListRules(ctx, gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to list rules")
		return fmt.Errorf("failed to check existing rules: %w", err)
	}

	for _, rule := range rules {
		if rule.ID == ruleUUID {
			continue
		}

		if rule.Path == updateReq.Path && rule.ServiceID == serviceUUID {
			s.logger.WithField("path", updateReq.Path).Error("rule with this path already exists for this service")
			return domain.ErrRuleAlreadyExists
		}
	}

	return nil
}

func (s *updateRuleHandler) applyRequestToDBRule(
	forwardingRule *forwarding_rule.ForwardingRule,
	updateReq req.UpdateRuleRequest,
) {
	if updateReq.Name != "" {
		forwardingRule.Name = updateReq.Name
	}

	if updateReq.Path != "" {
		forwardingRule.Path = updateReq.Path
	}

	if updateReq.Type != nil {
		ruleType := forwarding_rule.Type(*updateReq.Type)
		forwardingRule.Type = ruleType
	}

	if len(updateReq.Methods) > 0 {
		forwardingRule.Methods = updateReq.Methods
	}

	if updateReq.Headers != nil {
		forwardingRule.Headers = updateReq.Headers
	}

	if updateReq.StripPath != nil {
		forwardingRule.StripPath = *updateReq.StripPath
	}

	if updateReq.PreserveHost != nil {
		forwardingRule.PreserveHost = *updateReq.PreserveHost
	}

	if updateReq.RetryAttempts != nil {
		forwardingRule.RetryAttempts = *updateReq.RetryAttempts
	}

	if updateReq.Active != nil {
		forwardingRule.Active = *updateReq.Active
	}

	if updateReq.TrustLens != nil {
		forwardingRule.TrustLens = s.buildTrustLensConfig(updateReq.TrustLens)
	}

	if updateReq.PluginChain != nil {
		forwardingRule.PluginChain = s.buildPluginChain(updateReq.PluginChain)
	}
}

func (s *updateRuleHandler) buildTrustLensConfig(trustLens *types.TrustLensConfig) *domain.TrustLensJSON {
	return &domain.TrustLensJSON{
		AppID:   trustLens.AppID,
		TeamID:  trustLens.TeamID,
		Type:    trustLens.Type,
		Mapping: trustLens.Mapping,
	}
}

func (s *updateRuleHandler) buildPluginChain(pluginChain []types.PluginConfig) domain.PluginChainJSON {
	var pc domain.PluginChainJSON
	pc = append(pc, pluginChain...)
	return pc
}

func (s *updateRuleHandler) parseRequestBody(c *fiber.Ctx) (*req.UpdateRuleRequest, error) {
	var updateReq req.UpdateRuleRequest
	if err := c.BodyParser(&updateReq); err != nil {
		s.logger.WithError(err).Error("failed to bind request")
		return nil, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}
	return &updateReq, nil
}

func (s *updateRuleHandler) handleUpdateError(c *fiber.Ctx, err error) error {
	if errors.As(err, &domain.ErrEntityNotFound) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	if errors.Is(err, domain.ErrRuleAlreadyExists) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if errors.Is(err, domain.ErrInvalidRuleType) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	s.logger.WithError(err).Error("failed to update rule in database")
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
}

func (s *updateRuleHandler) updateRuleInCache(
	c *fiber.Ctx,
	gatewayID, ruleID string,
	updateReq req.UpdateRuleRequest,
) error {
	rules, err := s.getRulesFromCache(c.Context(), gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rules from cache")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	if err := s.applyRequestToCacheRule(rules, ruleID, updateReq); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
	}

	if err := s.saveRulesToCache(c.Context(), gatewayID, rules); err != nil {
		s.logger.WithError(err).Error("failed to save rules to cache")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	return nil
}

func (s *updateRuleHandler) getRulesFromCache(ctx context.Context, gatewayID string) ([]types.ForwardingRule, error) {
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(ctx, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rules")
		return nil, fmt.Errorf("failed to get rules from cache: %w", err)
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("failed to unmarshal rules")
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return rules, nil
}

func (s *updateRuleHandler) applyRequestToCacheRule(
	rules []types.ForwardingRule,
	ruleID string,
	updateReq req.UpdateRuleRequest,
) error {
	for i := range rules {
		if rules[i].ID != ruleID {
			continue
		}

		s.updateCacheRuleFields(&rules[i], updateReq)
		return nil
	}

	return fmt.Errorf("rule not found in cache")
}

func (s *updateRuleHandler) updateCacheRuleFields(
	rule *types.ForwardingRule,
	updateReq req.UpdateRuleRequest,
) {
	if updateReq.Name != "" {
		rule.Name = updateReq.Name
	}

	if updateReq.Path != "" {
		rule.Path = updateReq.Path
	}

	if updateReq.ServiceID != "" {
		rule.ServiceID = updateReq.ServiceID
	}

	if updateReq.Type != nil {
		rule.Type = *updateReq.Type
	}

	if len(updateReq.Methods) > 0 {
		rule.Methods = updateReq.Methods
	}

	if updateReq.Headers != nil {
		rule.Headers = s.copyHeaders(updateReq.Headers)
	}

	if updateReq.StripPath != nil {
		rule.StripPath = *updateReq.StripPath
	}

	if updateReq.Active != nil {
		rule.Active = *updateReq.Active
	}

	if updateReq.PreserveHost != nil {
		rule.PreserveHost = *updateReq.PreserveHost
	}

	if updateReq.RetryAttempts != nil {
		rule.RetryAttempts = *updateReq.RetryAttempts
	}

	if updateReq.PluginChain != nil {
		rule.PluginChain = s.convertPluginChainToCache(updateReq.PluginChain)
	}

	if updateReq.TrustLens != nil {
		rule.TrustLens = updateReq.TrustLens
	}
}

func (s *updateRuleHandler) convertPluginChainToCache(pluginChain []types.PluginConfig) []types.PluginConfig {
	if len(pluginChain) == 0 {
		return nil
	}

	chainJSON, err := json.Marshal(pluginChain)
	if err != nil {
		s.logger.WithError(err).Error("failed to marshal plugin chain")
		return pluginChain
	}

	var result []types.PluginConfig
	if err := json.Unmarshal(chainJSON, &result); err != nil {
		s.logger.WithError(err).Error("failed to unmarshal plugin chain")
		return pluginChain
	}

	return result
}

func (s *updateRuleHandler) copyHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string, len(headers))
	for k, v := range headers {
		result[k] = v
	}
	return result
}

func (s *updateRuleHandler) saveRulesToCache(
	ctx context.Context,
	gatewayID string,
	rules []types.ForwardingRule,
) error {
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		s.logger.WithError(err).Error("failed to marshal rules")
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	if err := s.cache.Set(ctx, rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("failed to save rules")
		return fmt.Errorf("failed to save rules to cache: %w", err)
	}

	return nil
}

func (s *updateRuleHandler) publishCacheInvalidation(ctx context.Context, gatewayID string) {
	if err := s.invalidationPublisher.Publish(
		ctx,
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{
			GatewayID: gatewayID,
		},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish cache invalidation")
	}
}

func (s *updateRuleHandler) validate(rule *req.UpdateRuleRequest) error {
	if err := s.validateHTTPMethods(rule.Methods); err != nil {
		return err
	}

	if err := s.validatePluginChain(rule.PluginChain); err != nil {
		return err
	}

	if err := s.validateTrustLens(rule.TrustLens); err != nil {
		return err
	}

	if err := s.validateRuleType(rule.Type); err != nil {
		return err
	}

	return nil
}

func (s *updateRuleHandler) validateHTTPMethods(methods []string) error {
	if len(methods) == 0 {
		return nil
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

	for _, method := range methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	return nil
}

func (s *updateRuleHandler) validatePluginChain(pluginChain []types.PluginConfig) error {
	if len(pluginChain) == 0 {
		return nil
	}

	for i, pl := range pluginChain {
		if err := s.validatePlugin.Validate(pl); err != nil {
			return fmt.Errorf("plugin %d: %v", i, err)
		}
	}

	return nil
}

func (s *updateRuleHandler) validateTrustLens(trustLens *types.TrustLensConfig) error {
	if trustLens == nil {
		return nil
	}

	if trustLens.AppID == "" {
		return fmt.Errorf("trust lens app id is required")
	}

	if trustLens.TeamID == "" {
		return fmt.Errorf("trust lens team id is required")
	}

	return nil
}

func (s *updateRuleHandler) validateRuleType(ruleType *string) error {
	if ruleType == nil {
		return nil
	}

	rt := forwarding_rule.Type(*ruleType)
	if rt != forwarding_rule.AgentRuleType && rt != forwarding_rule.EndpointRuleType {
		return domain.ErrInvalidRuleType
	}

	return nil
}
