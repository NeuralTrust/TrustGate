package rule

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=rule_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, gatewayID uuid.UUID, req *request.CreateRuleRequest) (*forwarding_rule.ForwardingRule, error)
}

type creator struct {
	logger               *logrus.Logger
	repo                 forwarding_rule.Repository
	gatewayRepo          gateway.Repository
	serviceRepo          service.Repository
	pluginChainValidator plugin.ValidatePluginChain
	publisher            infraCache.EventPublisher
	ruleMatcher          Matcher
}

func NewCreator(
	logger *logrus.Logger,
	repo forwarding_rule.Repository,
	gatewayRepo gateway.Repository,
	serviceRepo service.Repository,
	pluginChainValidator plugin.ValidatePluginChain,
	publisher infraCache.EventPublisher,
	ruleMatcher Matcher,
) Creator {
	return &creator{
		logger:               logger,
		repo:                 repo,
		gatewayRepo:          gatewayRepo,
		serviceRepo:          serviceRepo,
		pluginChainValidator: pluginChainValidator,
		publisher:            publisher,
		ruleMatcher:          ruleMatcher,
	}
}

func (c *creator) Create(
	ctx context.Context,
	gatewayID uuid.UUID,
	req *request.CreateRuleRequest,
) (*forwarding_rule.ForwardingRule, error) {
	serviceUUID, err := uuid.Parse(req.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid service ID", domain.ErrValidation)
	}

	if _, err = c.gatewayRepo.Get(ctx, gatewayID); err != nil {
		c.logger.WithError(err).WithField("gateway_id", gatewayID).Error("gateway not found")
		return nil, domain.ErrGatewayNotFound
	}

	if _, err = c.serviceRepo.Get(ctx, req.ServiceID); err != nil {
		c.logger.WithError(err).WithField("service_id", req.ServiceID).Error("service not found")
		return nil, domain.ErrServiceNotFound
	}

	stripPath := false
	if req.StripPath != nil {
		stripPath = *req.StripPath
	}

	preserveHost := false
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}

	retryAttempts := 0
	if req.RetryAttempts != nil {
		retryAttempts = *req.RetryAttempts
	}

	var trustLensConfig *domain.TrustLensJSON
	if req.TrustLens != nil {
		trustLensConfig = &domain.TrustLensJSON{
			TeamID:  req.TrustLens.TeamID,
			Mapping: req.TrustLens.Mapping,
		}
	}

	var pluginChainDB domain.PluginChainJSON
	if req.PluginChain != nil {
		pluginChainDB = append(pluginChainDB, req.PluginChain...)
	}

	ruleType := forwarding_rule.EndpointRuleType
	if req.Type != nil {
		ruleType = forwarding_rule.Type(*req.Type)
	}

	var sessionConfig *forwarding_rule.SessionConfig
	if req.SessionConfig != nil {
		sessionConfig = &forwarding_rule.SessionConfig{
			HeaderName:    req.SessionConfig.HeaderName,
			BodyParamName: req.SessionConfig.BodyParamName,
		}
	}

	var pathsDB domain.PathsJSON
	if req.Path.IsMultiPath() {
		pathsDB = domain.PathsJSON(req.Path.All)
	}

	dbRule, err := forwarding_rule.New(forwarding_rule.CreateParams{
		GatewayID:     gatewayID,
		ServiceID:     serviceUUID,
		Name:          req.Name,
		Path:          req.Path.Primary,
		Paths:         pathsDB,
		Type:          ruleType,
		Methods:       req.Methods,
		Headers:       domain.HeadersJSON(req.Headers),
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		PluginChain:   pluginChainDB,
		TrustLens:     trustLensConfig,
		SessionConfig: sessionConfig,
	})
	if err != nil {
		return nil, err
	}

	if len(req.PluginChain) > 0 {
		if err = c.pluginChainValidator.Validate(ctx, gatewayID, req.PluginChain); err != nil {
			c.logger.WithError(err).Error("failed to validate plugin chain")
			return nil, fmt.Errorf("%w: %v", domain.ErrValidation, err)
		}
	}

	if err := c.checkPathUniqueness(ctx, gatewayID, dbRule); err != nil {
		return nil, err
	}

	if err := c.repo.Create(ctx, dbRule); err != nil {
		c.logger.WithError(err).Error("failed to create rule")
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	if err := c.publisher.Publish(ctx, event.DeleteGatewayCacheEvent{GatewayID: gatewayID.String()}); err != nil {
		c.logger.WithError(err).Error("failed to publish cache invalidation")
	}

	return dbRule, nil
}

func (c *creator) checkPathUniqueness(ctx context.Context, gatewayID uuid.UUID, dbRule *forwarding_rule.ForwardingRule) error {
	rules, err := c.repo.ListRules(ctx, gatewayID)
	if err != nil {
		c.logger.WithError(err).Error("failed to list rules")
		return fmt.Errorf("failed to check existing rules: %w", err)
	}

	newPaths := dbRule.AllPaths()
	for _, existing := range rules {
		if existing.GatewayID != gatewayID {
			continue
		}
		for _, np := range newPaths {
			normalizedNew := c.ruleMatcher.NormalizePath(np)
			for _, ep := range existing.AllPaths() {
				if c.ruleMatcher.NormalizePath(ep) == normalizedNew {
					c.logger.WithField("path", np).Error("rule with this path already exists")
					return domain.ErrRuleAlreadyExists
				}
			}
		}
	}
	return nil
}
