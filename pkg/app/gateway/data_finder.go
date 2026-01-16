package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=DataFinder --dir=. --output=./mocks --filename=gateway_data_finder_mock.go --case=underscore --with-expecter
type DataFinder interface {
	Find(ctx context.Context, gatewayID uuid.UUID) (*types.GatewayData, error)
}

type dataFinder struct {
	repo              gateway.Repository
	ruleRepository    forwarding_rule.Repository
	cache             cache.Client
	memoryCache       *cache.TTLMap
	logger            *logrus.Logger
	outputTransformer *OutputTransformer
}

func NewDataFinder(
	repository gateway.Repository,
	ruleRepository forwarding_rule.Repository,
	c cache.Client,
	logger *logrus.Logger,
) DataFinder {
	return &dataFinder{
		repo:              repository,
		ruleRepository:    ruleRepository,
		cache:             c,
		logger:            logger,
		memoryCache:       c.GetTTLMap(cache.GatewayTTLName),
		outputTransformer: NewOutputTransformer(),
	}
}

func (f *dataFinder) Find(ctx context.Context, gatewayID uuid.UUID) (*types.GatewayData, error) {
	// Try memory cache first
	if cached, ok := f.memoryCache.Get(gatewayID.String()); ok {
		data, err := f.getGatewayDataFromCache(cached)
		if err != nil {
			f.logger.WithError(err).Warn("failed to get gateway data from cache")
		} else {
			return data, nil
		}
	}
	return f.getGatewayDataFromDB(ctx, gatewayID)
}

func (f *dataFinder) getGatewayDataFromCache(value interface{}) (*types.GatewayData, error) {
	data, ok := value.(*types.GatewayData)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion for gateway data")
	}
	return data, nil
}

func (f *dataFinder) convertModelToTypesGateway(g *gateway.Gateway) *types.GatewayDTO {
	return f.outputTransformer.convertGatewayToTypes(g)
}

func (f *dataFinder) getGatewayDataFromDB(ctx context.Context, gatewayID uuid.UUID) (*types.GatewayData, error) {
	entity, err := f.repo.Get(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from database: %w", err)
	}

	rules, err := f.ruleRepository.ListRules(ctx, gatewayID)
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

func (f *dataFinder) convertModelToTypesRules(rules []forwarding_rule.ForwardingRule) []types.ForwardingRuleDTO {
	var result []types.ForwardingRuleDTO
	for _, r := range rules {
		var pluginChain []pluginTypes.PluginConfig

		jsonBytes, err := f.getJSONBytes(r.PluginChain)
		if err != nil {
			return []types.ForwardingRuleDTO{}
		}

		if err := json.Unmarshal(jsonBytes, &pluginChain); err != nil {
			pluginChain = []pluginTypes.PluginConfig{} // fallback to empty slice on error
		}

		var trustLensConfig *types.TrustLensConfigDTO
		if r.TrustLens != nil {
			trustLensConfig = &types.TrustLensConfigDTO{
				TeamID:  r.TrustLens.TeamID,
				Type:    r.TrustLens.Type,
				Mapping: r.TrustLens.Mapping,
			}
		}

		result = append(result, types.ForwardingRuleDTO{
			ID:            r.ID.String(),
			GatewayID:     r.GatewayID.String(),
			Path:          r.Path,
			Type:          string(r.Type),
			ServiceID:     r.ServiceID.String(),
			Methods:       r.Methods,
			Headers:       r.Headers,
			StripPath:     r.StripPath,
			PreserveHost:  r.PreserveHost,
			RetryAttempts: r.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        r.Active,
			Public:        r.Public,
			TrustLens:     trustLensConfig,
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
