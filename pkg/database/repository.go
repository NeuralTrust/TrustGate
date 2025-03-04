package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

var (
	ErrRuleNotFound = fmt.Errorf("rule not found")
)

// Repository handles all database operations
type Repository struct {
	db     *gorm.DB
	logger logrus.FieldLogger
	cache  *cache.Cache
}

func NewRepository(db *gorm.DB, logger logrus.FieldLogger, cache *cache.Cache) *Repository {
	return &Repository{
		db:     db,
		logger: logger,
		cache:  cache,
	}
}
func (r *Repository) GetGateway(ctx context.Context, id string) (*models.Gateway, error) {
	var gateway models.Gateway
	if err := r.db.First(&gateway, "id = ?", id).Error; err != nil {
		return nil, err
	}
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return &gateway, nil
}

func (r *Repository) GetGatewayBySubdomain(ctx context.Context, subdomain string) (*models.Gateway, error) {
	var gateway models.Gateway
	err := r.db.Model(&models.Gateway{}).Where("subdomain = ?", subdomain).Take(&gateway).Error
	if err != nil {
		return nil, err
	}

	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}

	return &gateway, nil
}

func (r *Repository) ListGateways(ctx context.Context, offset, limit int) ([]models.Gateway, error) {
	var gateways []models.Gateway
	err := r.db.Model(&models.Gateway{}).
		Order("created_at desc").
		Limit(limit).
		Offset(offset).
		Find(&gateways).Error

	for i := range gateways {
		if gateways[i].RequiredPlugins == nil {
			gateways[i].RequiredPlugins = []types.PluginConfig{}
		}
	}

	return gateways, err
}

func (r *Repository) UpdateGateway(ctx context.Context, gateway *models.Gateway) error {
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return r.db.Save(gateway).Error
}

func (r *Repository) DeleteGateway(id string) error {
	// Start a transaction
	tx := r.db.Begin()
	tx = tx.Debug()
	if tx.Error != nil {
		return tx.Error
	}

	// Delete associated forwarding rules first
	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&models.ForwardingRule{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&models.Upstream{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&models.Service{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&models.APIKey{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Then delete the gateway
	if err := tx.Unscoped().Delete(&models.Gateway{ID: id}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction and check for errors
	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

// Forwarding Rule operations
func (r *Repository) CreateRule(ctx context.Context, rule *models.ForwardingRule) error {
	// Start a transaction
	tx := r.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// Create the rule
	if err := tx.Create(rule).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Get all rules for this gateway to update cache
	var rules []models.ForwardingRule
	if err := tx.Where("gateway_id = ?", rule.GatewayID).Find(&rules).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return err
	}

	// Update the rules cache after successful commit
	if err := r.UpdateRulesCache(ctx, rule.GatewayID, rules); err != nil {
		r.logger.WithError(err).Error("Failed to update rules cache after creation")
		// Don't return error here as the rule was created successfully
	}

	return nil
}

func (r *Repository) GetRule(ctx context.Context, id string, gatewayID string) (*models.ForwardingRule, error) {
	var rule models.ForwardingRule
	err := r.db.Where("id = ? AND gateway_id = ?", id, gatewayID).First(&rule).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *Repository) ListRules(ctx context.Context, gatewayID string) ([]models.ForwardingRule, error) {
	// Try cache first
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := r.cache.Get(ctx, rulesKey)
	if err == nil {
		var apiRules []types.ForwardingRule
		if err := json.Unmarshal([]byte(rulesJSON), &apiRules); err == nil {
			// Convert API rules back to DB models
			rules := make([]models.ForwardingRule, len(apiRules))
			for i, apiRule := range apiRules {
				rules[i] = models.ForwardingRule{
					ID:            apiRule.ID,
					GatewayID:     apiRule.GatewayID,
					Path:          apiRule.Path,
					ServiceID:     apiRule.ServiceID,
					Methods:       models.MethodsJSON(apiRule.Methods),
					Headers:       models.HeadersJSON(apiRule.Headers),
					StripPath:     apiRule.StripPath,
					PreserveHost:  apiRule.PreserveHost,
					RetryAttempts: apiRule.RetryAttempts,
					PluginChain:   models.PluginChainJSON(apiRule.PluginChain),
					Active:        apiRule.Active,
					Public:        apiRule.Public,
				}
				// Parse timestamps
				if t, err := time.Parse(time.RFC3339, apiRule.CreatedAt); err == nil {
					rules[i].CreatedAt = t
				}
				if t, err := time.Parse(time.RFC3339, apiRule.UpdatedAt); err == nil {
					rules[i].UpdatedAt = t
				}
			}
			return rules, nil
		}
		// If unmarshal fails, continue to database
	}

	// Get from database
	var rules []models.ForwardingRule
	err = r.db.Where("gateway_id = ?", gatewayID).Find(&rules).Error
	if err != nil {
		return nil, err
	}

	// Update cache with fresh data
	if err := r.UpdateRulesCache(ctx, gatewayID, rules); err != nil {
		r.logger.WithError(err).Error("Failed to update rules cache")
		// Continue anyway as we have the data
	}

	return rules, nil
}

func (r *Repository) UpdateRule(ctx context.Context, rule *models.ForwardingRule) error {
	result := r.db.Save(rule)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

func (r *Repository) DeleteRule(ctx context.Context, id, gatewayID string) error {
	result := r.db.WithContext(ctx).Unscoped().Where("id = ? AND gateway_id = ?", id, gatewayID).Delete(&models.ForwardingRule{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRuleNotFound
	}
	return nil
}

// API Key operations
func (r *Repository) CreateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	if apiKey.GatewayID == "" {
		return fmt.Errorf("gateway_id is required")
	}
	if apiKey.Name == "" {
		return fmt.Errorf("name is required")
	}
	if apiKey.Key == "" {
		return fmt.Errorf("key is required")
	}

	now := time.Now()
	if apiKey.CreatedAt.IsZero() {
		apiKey.CreatedAt = now
	}

	if !apiKey.Active {
		apiKey.Active = true
	}

	result := r.db.Create(apiKey)
	if result.Error != nil {
		return fmt.Errorf("failed to create API key: %w", result.Error)
	}

	return nil
}

func (r *Repository) GetAPIKey(ctx context.Context, id string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.db.Where("id = ?", id).First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

func (r *Repository) ListAPIKeys(ctx context.Context, gatewayID string) ([]models.APIKey, error) {
	var apiKeys []models.APIKey
	err := r.db.Where("gateway_id = ?", gatewayID).Find(&apiKeys).Error
	return apiKeys, err
}

func (r *Repository) UpdateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	result := r.db.Save(apiKey)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *Repository) DeleteAPIKey(ctx context.Context, id, gatewayID string) error {
	result := r.db.WithContext(ctx).Where("id = ? AND gateway_id = ?", id, gatewayID).Delete(&models.APIKey{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *Repository) SubdomainExists(ctx context.Context, subdomain string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Gateway{}).
		Where("subdomain = ?", subdomain).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check subdomain existence: %w", err)
	}
	return count > 0, nil
}

func (r *Repository) IsSubdomainAvailable(subdomain string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Gateway{}).Where("subdomain = ?", subdomain).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check subdomain: %w", err)
	}
	return count == 0, nil
}

func (r *Repository) ValidateAPIKey(ctx context.Context, gatewayID string, apiKey string) (bool, error) {
	var exists int64
	err := r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("gateway_id = ? AND key = ? AND (expires_at IS NULL OR expires_at > ?)",
			gatewayID, apiKey, time.Now()).
		Count(&exists).Error

	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// UpdateRulesCache updates the rules cache for a gateway
func (r *Repository) UpdateRulesCache(ctx context.Context, gatewayID string, rules []models.ForwardingRule) error {
	// Convert to API response format
	apiRules := make([]types.ForwardingRule, len(rules))
	for i, rule := range rules {
		// Ensure gateway ID is set
		if rule.GatewayID == "" {
			rule.GatewayID = gatewayID
		}

		// Ensure timestamps are set
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = time.Now()
		}
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = time.Now()
		}

		apiRules[i] = types.ForwardingRule{
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

		// Initialize empty maps if nil
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

// Upstream methods
func (r *Repository) CreateUpstream(ctx context.Context, upstream *models.Upstream) error {
	return r.db.WithContext(ctx).Create(upstream).Error
}

func (r *Repository) ListUpstreams(ctx context.Context, gatewayID string, offset, limit int) ([]models.Upstream, error) {
	var upstreams []models.Upstream
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID)

	if limit > 0 {
		query = query.Offset(offset).Limit(limit)
	}

	if err := query.Find(&upstreams).Error; err != nil {
		return nil, err
	}
	return upstreams, nil
}

func (r *Repository) UpdateUpstream(ctx context.Context, upstream *models.Upstream) error {
	return r.db.WithContext(ctx).Save(upstream).Error
}

func (r *Repository) DeleteUpstream(ctx context.Context, id string) error {
	// First check if the upstream is being used by any services
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.Service{}).Where("upstream_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("upstream is being used by %d services", count)
	}

	return r.db.WithContext(ctx).Delete(&models.Upstream{}, "id = ?", id).Error
}

// Service methods
func (r *Repository) CreateService(ctx context.Context, service *models.Service) error {
	// Verify upstream exists and belongs to the same gateway
	var upstream models.Upstream
	if err := r.db.WithContext(ctx).Where("id = ? AND gateway_id = ?", service.UpstreamID, service.GatewayID).First(&upstream).Error; err != nil {
		return fmt.Errorf("invalid upstream_id or upstream belongs to different gateway: %w", err)
	}

	return r.db.WithContext(ctx).Create(service).Error
}

func (r *Repository) ListServices(ctx context.Context, gatewayID string, offset, limit int) ([]models.Service, error) {
	var services []models.Service
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID).Preload("Upstream")

	if limit > 0 {
		query = query.Offset(offset).Limit(limit)
	}

	if err := query.Find(&services).Error; err != nil {
		return nil, err
	}
	return services, nil
}

func (r *Repository) UpdateService(ctx context.Context, service *models.Service) error {
	// Verify upstream exists and belongs to the same gateway
	var upstream models.Upstream
	if err := r.db.WithContext(ctx).Where("id = ? AND gateway_id = ?", service.UpstreamID, service.GatewayID).First(&upstream).Error; err != nil {
		return fmt.Errorf("invalid upstream_id or upstream belongs to different gateway: %w", err)
	}

	return r.db.WithContext(ctx).Save(service).Error
}

func (r *Repository) DeleteService(ctx context.Context, id string) error {
	// First check if the service is being used by any forwarding rules
	var count int64
	if err := r.db.WithContext(ctx).Model(&models.ForwardingRule{}).Where("service_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("service is being used by %d forwarding rules", count)
	}

	return r.db.WithContext(ctx).Delete(&models.Service{}, "id = ?", id).Error
}
