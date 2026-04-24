package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=rule_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, gatewayID, ruleID uuid.UUID, req *request.UpdateRuleRequest) error
}

type updater struct {
	logger                *logrus.Logger
	repo                  forwarding_rule.Repository
	cache                 cache.Client
	validatePlugin        *plugin.ValidatePlugin
	invalidationPublisher cache.EventPublisher
	ruleMatcher           Matcher
}

func NewUpdater(
	logger *logrus.Logger,
	repo forwarding_rule.Repository,
	cache cache.Client,
	validatePlugin *plugin.ValidatePlugin,
	invalidationPublisher cache.EventPublisher,
	ruleMatcher Matcher,
) Updater {
	return &updater{
		logger:                logger,
		repo:                  repo,
		cache:                 cache,
		validatePlugin:        validatePlugin,
		invalidationPublisher: invalidationPublisher,
		ruleMatcher:           ruleMatcher,
	}
}

func (u *updater) Update(ctx context.Context, gatewayID, ruleID uuid.UUID, req *request.UpdateRuleRequest) error {
	if len(req.PluginChain) > 0 {
		for i, pl := range req.PluginChain {
			if err := u.validatePlugin.Validate(pl); err != nil {
				return fmt.Errorf("%w: plugin %d: %v", domain.ErrValidation, i, err)
			}
		}
	}

	if err := u.updateForwardingRuleDB(ctx, ruleID, gatewayID, req); err != nil {
		return err
	}

	if err := u.updateRuleInCache(ctx, gatewayID.String(), ruleID.String(), req); err != nil {
		return err
	}

	u.publishCacheInvalidation(ctx, gatewayID.String())

	return nil
}

func (u *updater) updateForwardingRuleDB(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
	updateReq *request.UpdateRuleRequest,
) error {
	fwdRule, err := u.repo.GetRule(ctx, ruleUUID, gatewayUUID)
	if err != nil {
		u.logger.WithError(err).Error("failed to get rule")
		return fmt.Errorf("failed to get rule: %w", err)
	}
	if fwdRule == nil {
		return domain.NewNotFoundError("rule", ruleUUID)
	}

	serviceUUID, err := u.parseAndUpdateServiceID(fwdRule, updateReq)
	if err != nil {
		return err
	}

	if err := u.validateRuleUniqueness(ctx, ruleUUID, gatewayUUID, updateReq, serviceUUID); err != nil {
		return err
	}

	u.applyRequestToDBRule(fwdRule, updateReq)
	fwdRule.UpdatedAt = time.Now()

	if err := u.repo.Update(ctx, fwdRule); err != nil {
		u.logger.WithError(err).Error("failed to update rule")
		return fmt.Errorf("failed to update rule: %w", err)
	}

	return nil
}

func (u *updater) parseAndUpdateServiceID(
	fwdRule *forwarding_rule.ForwardingRule,
	updateReq *request.UpdateRuleRequest,
) (uuid.UUID, error) {
	if updateReq.ServiceID == "" {
		return uuid.Nil, nil
	}

	serviceUUID, err := uuid.Parse(updateReq.ServiceID)
	if err != nil {
		u.logger.WithError(err).Error("failed to parse service ID")
		return uuid.Nil, fmt.Errorf("%w: invalid service ID", domain.ErrValidation)
	}

	fwdRule.ServiceID = serviceUUID
	return serviceUUID, nil
}

func (u *updater) validateRuleUniqueness(
	ctx context.Context,
	ruleUUID, gatewayUUID uuid.UUID,
	updateReq *request.UpdateRuleRequest,
	serviceUUID uuid.UUID,
) error {
	if updateReq.Path == nil || serviceUUID == uuid.Nil {
		return nil
	}

	rules, err := u.repo.ListRules(ctx, gatewayUUID)
	if err != nil {
		u.logger.WithError(err).Error("failed to list rules")
		return fmt.Errorf("failed to check existing rules: %w", err)
	}

	var updatePaths []string
	if updateReq.Path.IsMultiPath() {
		updatePaths = updateReq.Path.All
	} else {
		updatePaths = []string{updateReq.Path.Primary}
	}

	for _, existing := range rules {
		if existing.ID == ruleUUID {
			continue
		}
		for _, np := range updatePaths {
			normalizedNew := u.ruleMatcher.NormalizePath(np)
			for _, ep := range existing.AllPaths() {
				if u.ruleMatcher.NormalizePath(ep) == normalizedNew && existing.ServiceID == serviceUUID {
					u.logger.WithField("path", np).Error("rule with this path already exists for this service")
					return domain.ErrRuleAlreadyExists
				}
			}
		}
	}

	return nil
}

func (u *updater) applyRequestToDBRule(fwdRule *forwarding_rule.ForwardingRule, updateReq *request.UpdateRuleRequest) {
	if updateReq.Name != "" {
		fwdRule.Name = updateReq.Name
	}

	if updateReq.Path != nil {
		fwdRule.Path = updateReq.Path.Primary
		if updateReq.Path.IsMultiPath() {
			fwdRule.Paths = updateReq.Path.All
		} else {
			fwdRule.Paths = nil
		}
	}

	if updateReq.Type != nil {
		fwdRule.Type = forwarding_rule.Type(*updateReq.Type)
	}

	if len(updateReq.Methods) > 0 {
		fwdRule.Methods = updateReq.Methods
	}

	if updateReq.Headers != nil {
		fwdRule.Headers = updateReq.Headers
	}

	if updateReq.StripPath != nil {
		fwdRule.StripPath = *updateReq.StripPath
	}

	if updateReq.PreserveHost != nil {
		fwdRule.PreserveHost = *updateReq.PreserveHost
	}

	if updateReq.RetryAttempts != nil {
		fwdRule.RetryAttempts = *updateReq.RetryAttempts
	}

	if updateReq.Active != nil {
		fwdRule.Active = *updateReq.Active
	}

	if updateReq.TrustLens != nil {
		fwdRule.TrustLens = &domain.TrustLensJSON{
			TeamID:  updateReq.TrustLens.TeamID,
			Mapping: updateReq.TrustLens.Mapping,
		}
	}

	if updateReq.PluginChain != nil {
		var pc domain.PluginChainJSON
		pc = append(pc, updateReq.PluginChain...)
		fwdRule.PluginChain = pc
	}

	if updateReq.SessionConfig != nil {
		fwdRule.SessionConfig = &forwarding_rule.SessionConfig{
			HeaderName:    updateReq.SessionConfig.HeaderName,
			BodyParamName: updateReq.SessionConfig.BodyParamName,
		}
	}
}

func (u *updater) updateRuleInCache(ctx context.Context, gatewayID, ruleID string, updateReq *request.UpdateRuleRequest) error {
	rules, err := u.getRulesFromCache(ctx, gatewayID)
	if err != nil {
		u.logger.WithError(err).Error("failed to get rules from cache")
		return fmt.Errorf("failed to get rules from cache: %w", err)
	}

	if err := u.applyRequestToCacheRule(rules, ruleID, updateReq); err != nil {
		return domain.NewNotFoundError("rule in cache", uuid.Nil)
	}

	if err := u.saveRulesToCache(ctx, gatewayID, rules); err != nil {
		u.logger.WithError(err).Error("failed to save rules to cache")
		return fmt.Errorf("failed to save rules to cache: %w", err)
	}

	return nil
}

func (u *updater) getRulesFromCache(ctx context.Context, gatewayID string) ([]types.ForwardingRuleDTO, error) {
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := u.cache.Get(ctx, rulesKey)
	if err != nil {
		u.logger.WithError(err).Error("failed to get rules")
		return nil, fmt.Errorf("failed to get rules from cache: %w", err)
	}

	var rules []types.ForwardingRuleDTO
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		u.logger.WithError(err).Error("failed to unmarshal rules")
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	return rules, nil
}

func (u *updater) applyRequestToCacheRule(rules []types.ForwardingRuleDTO, ruleID string, updateReq *request.UpdateRuleRequest) error {
	for i := range rules {
		if rules[i].ID != ruleID {
			continue
		}
		u.updateCacheRuleFields(&rules[i], updateReq)
		return nil
	}
	return fmt.Errorf("rule not found in cache")
}

func (u *updater) updateCacheRuleFields(rule *types.ForwardingRuleDTO, updateReq *request.UpdateRuleRequest) {
	if updateReq.Name != "" {
		rule.Name = updateReq.Name
	}

	if updateReq.Path != nil {
		rule.Path = updateReq.Path.Primary
		if updateReq.Path.IsMultiPath() {
			rule.Paths = updateReq.Path.All
		} else {
			rule.Paths = nil
		}
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
		result := make(map[string]string, len(updateReq.Headers))
		for k, v := range updateReq.Headers {
			result[k] = v
		}
		rule.Headers = result
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
		rule.PluginChain = u.convertPluginChainToCache(updateReq.PluginChain)
	}

	if updateReq.TrustLens != nil {
		rule.TrustLens = updateReq.TrustLens
	}

	if updateReq.SessionConfig != nil {
		rule.SessionConfig = updateReq.SessionConfig
	}
}

func (u *updater) convertPluginChainToCache(pluginChain []pluginTypes.PluginConfig) []pluginTypes.PluginConfig {
	if len(pluginChain) == 0 {
		return nil
	}

	chainJSON, err := json.Marshal(pluginChain)
	if err != nil {
		u.logger.WithError(err).Error("failed to marshal plugin chain")
		return pluginChain
	}

	var result []pluginTypes.PluginConfig
	if err := json.Unmarshal(chainJSON, &result); err != nil {
		u.logger.WithError(err).Error("failed to unmarshal plugin chain")
		return pluginChain
	}

	return result
}

func (u *updater) saveRulesToCache(ctx context.Context, gatewayID string, rules []types.ForwardingRuleDTO) error {
	SortBySpecificity(rules)

	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		u.logger.WithError(err).Error("failed to marshal rules")
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	if err := u.cache.Set(ctx, rulesKey, string(updatedJSON), 0); err != nil {
		u.logger.WithError(err).Error("failed to save rules")
		return fmt.Errorf("failed to save rules to cache: %w", err)
	}

	return nil
}

func (u *updater) publishCacheInvalidation(ctx context.Context, gatewayID string) {
	if err := u.invalidationPublisher.Publish(ctx, event.DeleteGatewayCacheEvent{GatewayID: gatewayID}); err != nil {
		u.logger.WithError(err).Error("failed to publish cache invalidation")
	}
}
