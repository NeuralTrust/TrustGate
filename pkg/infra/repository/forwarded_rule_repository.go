package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var (
	ErrRuleNotFound = fmt.Errorf("rule not found")
)

type forwardedRuleRepository struct {
	db     *gorm.DB
	logger *logrus.Logger
	cache  *cache.Cache
}

func NewForwardedRuleRepository(db *gorm.DB, logger *logrus.Logger, cache *cache.Cache) forwarding_rule.Repository {
	return &forwardedRuleRepository{
		db:     db,
		logger: logger,
		cache:  cache,
	}
}

func (r *forwardedRuleRepository) Create(ctx context.Context, rule *forwarding_rule.ForwardingRule) error {
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	if err := tx.Create(rule).Error; err != nil {
		tx.Rollback()
		return err
	}
	var rules []forwarding_rule.ForwardingRule
	if err := tx.Where("gateway_id = ?", rule.GatewayID).Find(&rules).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit().Error; err != nil {
		return err
	}
	return nil
}

func (r *forwardedRuleRepository) ListRules(
	ctx context.Context,
	gatewayID uuid.UUID,
) ([]forwarding_rule.ForwardingRule, error) {
	var rules []forwarding_rule.ForwardingRule
	err := r.db.Where("gateway_id = ?", gatewayID).Find(&rules).Error
	if err != nil {
		return nil, err
	}

	if err := r.UpdateRulesCache(ctx, gatewayID, rules); err != nil {
		r.logger.WithError(err).Error("failed to update rules cache")
	}

	return rules, nil
}

func (r *forwardedRuleRepository) Update(ctx context.Context, rule *forwarding_rule.ForwardingRule) error {
	result := r.db.WithContext(ctx).Save(rule)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

func (r *forwardedRuleRepository) Delete(ctx context.Context, id, gatewayID uuid.UUID) error {
	result := r.db.WithContext(ctx).Unscoped().Where("id = ? AND gateway_id = ?", id, gatewayID).
		Delete(&forwarding_rule.ForwardingRule{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRuleNotFound
	}
	return nil
}

func (r *forwardedRuleRepository) GetRule(
	ctx context.Context,
	id uuid.UUID,
	gatewayID uuid.UUID,
) (*forwarding_rule.ForwardingRule, error) {
	var rule forwarding_rule.ForwardingRule
	err := r.db.WithContext(ctx).Where("id = ? AND gateway_id = ?", id, gatewayID).First(&rule).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *forwardedRuleRepository) GetRuleByID(ctx context.Context, id uuid.UUID) (*forwarding_rule.ForwardingRule, error) {
	var rule forwarding_rule.ForwardingRule
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&rule).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *forwardedRuleRepository) UpdateRulesCache(
	ctx context.Context,
	gatewayID uuid.UUID,
	rules []forwarding_rule.ForwardingRule,
) error {
	apiRules := make([]types.ForwardingRule, len(rules))
	for i, rule := range rules {
		if rule.GatewayID == uuid.Nil {
			rule.GatewayID = gatewayID
		}

		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = time.Now()
		}
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = time.Now()
		}

		var trustLensConfig *types.TrustLensConfig
		if rule.TrustLens != nil {
			trustLensConfig = &types.TrustLensConfig{
				AppID:  rule.TrustLens.AppID,
				TeamID: rule.TrustLens.TeamID,
			}
		}

		apiRules[i] = types.ForwardingRule{
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
			TrustLens:     trustLensConfig,
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}

		if apiRules[i].Headers == nil {
			apiRules[i].Headers = make(map[string]string)
		}
	}

	// Marshal rules to JSON
	rulesJSON, err := json.Marshal(apiRules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
		"rules":     string(rulesJSON),
	}).Debug("Caching rules")

	// Store in cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := r.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		return fmt.Errorf("failed to cache rules: %w", err)
	}

	return nil
}
