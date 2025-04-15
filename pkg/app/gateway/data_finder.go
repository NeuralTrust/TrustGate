package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type DataFinder interface {
	Find(ctx context.Context, gatewayID string) (*types.GatewayData, error)
}

type dataFinder struct {
	repo        *database.Repository
	cache       *cache.Cache
	memoryCache *common.TTLMap
	logger      *logrus.Logger
}

func NewDataFinder(
	repository *database.Repository,
	c *cache.Cache,
	logger *logrus.Logger,
) DataFinder {
	return &dataFinder{
		repo:        repository,
		cache:       c,
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.GatewayTTLName),
	}
}

func (f *dataFinder) Find(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Try memory cache first
	if cached, ok := f.memoryCache.Get(gatewayID); ok {
		data, err := f.getGatewayDataFromCache(cached)
		if err != nil {
			f.logger.WithError(err).Error("failed to get gateway data from cache")
		} else {
			return data, nil
		}
	}
	// Try Redis cache
	gatewayData, err := f.getGatewayDataFromRedis(ctx, gatewayID)
	if err == nil {
		f.logger.WithFields(logrus.Fields{
			"gatewayID":  gatewayID,
			"rulesCount": len(gatewayData.Rules),
			"fromCache":  "redis",
		}).Debug("Gateway data found in Redis cache")

		// Store in memory cache
		f.memoryCache.Set(gatewayID, gatewayData)
		return gatewayData, nil
	}
	f.logger.WithError(err).Debug("Failed to get gateway data from Redis")

	// Fallback to database
	gatewayIDUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway ID format: %w", err)
	}
	return f.getGatewayDataFromDB(ctx, gatewayIDUUID)
}

func (f *dataFinder) getGatewayDataFromCache(value interface{}) (*types.GatewayData, error) {
	data, ok := value.(*types.GatewayData)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion for gateway data")
	}
	return data, nil
}

func (f *dataFinder) getGatewayDataFromRedis(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Get gateway from Redis
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	gatewayJSON, err := f.cache.Get(ctx, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from Redis: %w", err)
	}

	var entity *gateway.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &entity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gateway from Redis: %w", err)
	}

	// Get rules from Redis
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := f.cache.Get(ctx, rulesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from Redis: %w", err)
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules from Redis: %w", err)
	}

	return &types.GatewayData{
		Gateway: f.convertModelToTypesGateway(entity),
		Rules:   rules,
	}, nil
}

func (f *dataFinder) convertModelToTypesGateway(g *gateway.Gateway) *types.Gateway {
	var requiredPlugins []types.PluginConfig
	for _, pluginConfig := range g.RequiredPlugins {
		requiredPlugins = append(requiredPlugins, pluginConfig)
	}
	var requiredTelemetry []types.Exporter
	if g.Telemetry != nil {
		for _, telemetryConfig := range g.Telemetry.Exporters {
			requiredTelemetry = append(requiredTelemetry, types.Exporter{
				Name:     telemetryConfig.Name,
				Settings: telemetryConfig.Settings,
			})
		}
	}
	var securityConfig *types.SecurityConfig
	if g.SecurityConfig != nil {
		securityConfig = &types.SecurityConfig{
			AllowedHosts:            g.SecurityConfig.AllowedHosts,
			AllowedHostsAreRegex:    g.SecurityConfig.AllowedHostsAreRegex,
			SSLRedirect:             g.SecurityConfig.SSLRedirect,
			SSLHost:                 g.SecurityConfig.SSLHost,
			SSLProxyHeaders:         g.SecurityConfig.SSLProxyHeaders,
			STSSeconds:              g.SecurityConfig.STSSeconds,
			STSIncludeSubdomains:    g.SecurityConfig.STSIncludeSubdomains,
			FrameDeny:               g.SecurityConfig.FrameDeny,
			CustomFrameOptionsValue: g.SecurityConfig.CustomFrameOptionsValue,
			ReferrerPolicy:          g.SecurityConfig.ReferrerPolicy,
			ContentSecurityPolicy:   g.SecurityConfig.ContentSecurityPolicy,
			ContentTypeNosniff:      g.SecurityConfig.ContentTypeNosniff,
			BrowserXSSFilter:        g.SecurityConfig.BrowserXSSFilter,
			IsDevelopment:           g.SecurityConfig.IsDevelopment,
		}
	}

	return &types.Gateway{
		ID:              g.ID.String(),
		Name:            g.Name,
		Subdomain:       g.Subdomain,
		Status:          g.Status,
		RequiredPlugins: requiredPlugins,
		SecurityConfig:  securityConfig,
		Telemetry: &types.Telemetry{
			Exporters:           requiredTelemetry,
			ExtraParams:         g.Telemetry.ExtraParams,
			EnablePluginTraces:  g.Telemetry.EnablePluginTraces,
			EnableRequestTraces: g.Telemetry.EnableRequestTraces,
		},
	}
}

func (f *dataFinder) getGatewayDataFromDB(ctx context.Context, gatewayID uuid.UUID) (*types.GatewayData, error) {
	entity, err := f.repo.GetGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from database: %w", err)
	}

	rules, err := f.repo.ListRules(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from database: %w", err)
	}

	gatewayData := &types.GatewayData{
		Gateway: f.convertModelToTypesGateway(entity),
		Rules:   f.convertModelToTypesRules(rules),
	}

	// Cache the results
	if err := f.cacheGatewayData(ctx, gatewayID.String(), entity, rules); err != nil {
		f.logger.WithError(err).Warn("Failed to cache gateway data")
	}

	f.logger.WithFields(logrus.Fields{
		"gatewayID":       gatewayID,
		"requiredPlugins": entity.RequiredPlugins,
		"rulesCount":      len(rules),
		"fromCache":       "database",
	}).Debug("Loaded gateway data from database")

	return gatewayData, nil
}

func (f *dataFinder) convertModelToTypesRules(rules []forwarding_rule.ForwardingRule) []types.ForwardingRule {
	var result []types.ForwardingRule
	for _, r := range rules {
		var pluginChain []types.PluginConfig

		jsonBytes, err := f.getJSONBytes(r.PluginChain)
		if err != nil {
			return []types.ForwardingRule{}
		}

		if err := json.Unmarshal(jsonBytes, &pluginChain); err != nil {
			pluginChain = []types.PluginConfig{} // fallback to empty slice on error
		}

		result = append(result, types.ForwardingRule{
			ID:            r.ID.String(),
			GatewayID:     r.GatewayID.String(),
			Path:          r.Path,
			ServiceID:     r.ServiceID.String(),
			Methods:       r.Methods,
			Headers:       r.Headers,
			StripPath:     r.StripPath,
			PreserveHost:  r.PreserveHost,
			RetryAttempts: r.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        r.Active,
			Public:        r.Public,
			CreatedAt:     r.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     r.UpdatedAt.Format(time.RFC3339),
		})
	}
	return result
}

func (f *dataFinder) cacheGatewayData(
	ctx context.Context,
	gatewayID string,
	gateway *gateway.Gateway,
	rules []forwarding_rule.ForwardingRule,
) error {
	// Cache gateway
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	if err := f.cache.Set(ctx, gatewayKey, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	// Convert and cache rules as types
	typesRules := f.convertModelToTypesRules(rules)
	rulesJSON, err := json.Marshal(typesRules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := f.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		return fmt.Errorf("failed to cache rules: %w", err)
	}

	// Cache in memory
	gatewayData := &types.GatewayData{
		Gateway: f.convertModelToTypesGateway(gateway),
		Rules:   typesRules,
	}

	f.memoryCache.Set(gatewayID, gatewayData)

	return nil
}

func (f *dataFinder) getJSONBytes(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case json.RawMessage:
		return v, nil
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value to JSON bytes: %w", err)
		}
		return b, nil
	}
}
