package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/response"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type listRulesHandler struct {
	logger      *logrus.Logger
	ruleRepo    forwarding_rule.Repository
	gatewayRepo gateway.Repository
	serviceRepo service.Repository
	cache       *cache.Cache
}

func NewListRulesHandler(
	logger *logrus.Logger,
	ruleRepo forwarding_rule.Repository,
	gatewayRepo gateway.Repository,
	serviceRepo service.Repository,
	cache *cache.Cache,
) Handler {
	return &listRulesHandler{
		logger:      logger,
		ruleRepo:    ruleRepo,
		gatewayRepo: gatewayRepo,
		serviceRepo: serviceRepo,
		cache:       cache,
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

	gw, err := s.gatewayRepo.GetGateway(c.Context(), gatewayUUID)

	if err != nil {
		if errors.As(err, &domain.ErrEntityNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
		}
		s.logger.WithError(err).Error("failed to get gateway from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get gateway"})
	}

	dbRules, err := s.ruleRepo.ListRules(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get rules from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list rules"})
	}

	rules := make([]types.ForwardingRule, len(dbRules))
	rulesOutput := make([]response.ForwardingRuleOutput, len(dbRules))
	for i, rule := range dbRules {
		var trustLensConfig *types.TrustLensConfig
		if rule.TrustLens != nil {
			trustLensConfig = &types.TrustLensConfig{
				AppID:  rule.TrustLens.AppID,
				TeamID: rule.TrustLens.TeamID,
			}
		}
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
			TrustLens:     trustLensConfig,
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}

		srv, err := s.serviceRepo.GetService(c.Context(), rule.ServiceID.String())
		if err != nil {
			s.logger.WithError(err).Error("failed to get service from database")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get service"})
		}
		var upstreamOutput *response.UpstreamOutput
		if srv != nil {
			if srv.Upstream != nil {
				upstreamOutput = &response.UpstreamOutput{
					Name:      srv.Upstream.Name,
					Algorithm: srv.Upstream.Algorithm,
					Targets:   srv.Upstream.Targets,
				}
			}
		}
		rulesOutput[i] = response.ForwardingRuleOutput{
			ID:          rule.ID.String(),
			Upstream:    upstreamOutput,
			ServiceID:   rule.ServiceID.String(),
			Path:        rule.Path,
			Methods:     rule.Methods,
			Headers:     rule.Headers,
			PluginChain: rule.PluginChain,
			Active:      rule.Active,
			TrustLens:   rule.TrustLens,
			CreatedAt:   rule.CreatedAt,
			UpdatedAt:   rule.UpdatedAt,
		}
	}

	rulesJSON, err := json.Marshal(rules)
	if err == nil {
		rulesKey := fmt.Sprintf("rules:%s", gatewayID)
		if err := s.cache.Set(c.Context(), rulesKey, string(rulesJSON), 0); err != nil {
			s.logger.WithError(err).Warn("failed to cache rules")
		}
	}

	output := response.ListRulesOutput{
		Gateway: response.GatewayOutput{
			ID:              gw.ID.String(),
			Status:          gw.Status,
			RequiredPlugins: gw.RequiredPlugins,
			CreatedAt:       gw.CreatedAt,
			UpdatedAt:       gw.UpdatedAt,
		},
		Rules: rulesOutput,
	}

	return c.Status(fiber.StatusOK).JSON(output)
}
