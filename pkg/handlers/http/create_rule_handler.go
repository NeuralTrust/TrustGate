package http

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createRuleHandler struct {
	logger               *logrus.Logger
	repo                 forwarding_rule.Repository
	gatewayRepo          gateway.Repository
	serviceRepo          service.Repository
	pluginChainValidator plugin.ValidatePluginChain
	publisher            infraCache.EventPublisher
}

func NewCreateRuleHandler(
	logger *logrus.Logger,
	repo forwarding_rule.Repository,
	gatewayRepo gateway.Repository,
	serviceRepo service.Repository,
	pluginChainValidator plugin.ValidatePluginChain,
	publisher infraCache.EventPublisher,
) Handler {
	return &createRuleHandler{
		logger:               logger,
		repo:                 repo,
		gatewayRepo:          gatewayRepo,
		serviceRepo:          serviceRepo,
		pluginChainValidator: pluginChainValidator,
		publisher:            publisher,
	}
}

// Handle @Summary Create a new Rule
// @Description Adds a new rule under a gateway
// @Tags Rules
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param rule body types.CreateRuleRequest true "Rule request body"
// @Success 201 {object} forwarding_rule.ForwardingRule "Rule created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/gateways/{gateway_id}/rules [post]
func (s *createRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var req types.CreateRuleRequest

	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	// Validate the rule request
	if err := s.validate(&req); err != nil {
		s.logger.WithError(err).Error("Failed to validate rule")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Convert headers to map[string]string format
	headers := make(map[string]string)
	for k, v := range req.Headers {
		headers[k] = v
	}

	// Set default values for optional fields
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

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return fmt.Errorf("failed to parse gateway ID: %v", err)
	}

	serviceUUID, err := uuid.Parse(req.ServiceID)
	if err != nil {
		return fmt.Errorf("failed to parse service ID: %v", err)
	}

	// Validate that gateway exists
	_, err = s.gatewayRepo.Get(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Gateway not found")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
	}

	// Validate that service exists
	_, err = s.serviceRepo.Get(c.Context(), req.ServiceID)
	if err != nil {
		s.logger.WithError(err).WithField("service_id", req.ServiceID).Error("Service not found")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Service not found"})
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
	}

	var trustLensConfig *domain.TrustLensJSON
	if req.TrustLens != nil {
		if req.TrustLens.AppID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "trust lens app id is required"})
		}
		if req.TrustLens.TeamID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "trust lens team id is required"})
		}
		trustLensConfig = &domain.TrustLensJSON{
			AppID:   req.TrustLens.AppID,
			TeamID:  req.TrustLens.TeamID,
			Type:    req.TrustLens.Type,
			Mapping: req.TrustLens.Mapping,
		}
	}

	dbRule := &forwarding_rule.ForwardingRule{
		ID:            id,
		Name:          req.Name,
		GatewayID:     gatewayUUID,
		Path:          req.Path,
		ServiceID:     serviceUUID,
		Methods:       req.Methods,
		Headers:       domain.HeadersJSON(req.Headers),
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		PluginChain:   req.PluginChain,
		Active:        true,
		Public:        false,
		TrustLens:     trustLensConfig,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if len(req.PluginChain) > 0 {
		err = s.pluginChainValidator.Validate(c.Context(), gatewayUUID, req.PluginChain)
		if err != nil {
			s.logger.WithError(err).Error("failed to validate plugin chain")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	// Check if a rule with the same path already exists for this gateway and service
	rules, err := s.repo.ListRules(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list rules")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to check existing rules"})
	}

	for _, rule := range rules {
		if rule.Path == req.Path && rule.GatewayID == gatewayUUID {
			s.logger.WithField("path", req.Path).Error("rule with this path already exists for this service")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "rule already exists"})
		}
	}

	if err := s.repo.Create(c.Context(), dbRule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create rule"})
	}

	response, err := s.getRuleResponse(dbRule)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rule response")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process rule"})
	}

	if err := s.publisher.Publish(
		c.Context(),
		channel.GatewayEventsChannel,
		event.DeleteGatewayCacheEvent{GatewayID: gatewayID},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish cache invalidation")
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (s *createRuleHandler) getRuleResponse(rule *forwarding_rule.ForwardingRule) (types.ForwardingRule, error) {
	var pluginChain []types.PluginConfig
	if rule.PluginChain != nil {
		chainJSON, err := json.Marshal(rule.PluginChain)
		if err != nil {
			return types.ForwardingRule{}, fmt.Errorf("failed to marshal plugin chain: %w", err)
		}
		if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
			return types.ForwardingRule{}, fmt.Errorf("failed to unmarshal plugin chain: %w", err)
		}
	}

	headers := make(map[string]string)
	for _, h := range rule.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	var trustLensConfig *types.TrustLensConfig
	if rule.TrustLens != nil {
		trustLensConfig = &types.TrustLensConfig{
			AppID:   rule.TrustLens.AppID,
			TeamID:  rule.TrustLens.TeamID,
			Type:    rule.TrustLens.Type,
			Mapping: rule.TrustLens.Mapping,
		}
	}

	return types.ForwardingRule{
		ID:            rule.ID.String(),
		Name:          rule.Name,
		GatewayID:     rule.GatewayID.String(),
		Path:          rule.Path,
		ServiceID:     rule.ServiceID.String(),
		Methods:       rule.Methods,
		Headers:       headers,
		StripPath:     rule.StripPath,
		PreserveHost:  rule.PreserveHost,
		RetryAttempts: rule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        rule.Active,
		Public:        rule.Public,
		TrustLens:     trustLensConfig,
		CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
	}, nil
}

func (s *createRuleHandler) validate(rule *types.CreateRuleRequest) error {

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

	if rule.TrustLens != nil {
		if rule.TrustLens.AppID == "" {
			return fmt.Errorf("trust lens app id is required")
		}
		if rule.TrustLens.TeamID == "" {
			return fmt.Errorf("trust lens team id is required")
		}

		// Validate Type field if provided
		if rule.TrustLens.Type != "" {
			validTypes := map[string]bool{
				"MESSAGE":    true,
				"TOOL":       true,
				"AGENT":      true,
				"RETRIEVAL":  true,
				"GENERATION": true,
				"ROUTER":     true,
				"SYSTEM":     true,
				"FEEDBACK":   true,
			}

			if !validTypes[strings.ToUpper(rule.TrustLens.Type)] {
				return fmt.Errorf("invalid trust lens type: %s. Must be one of: MESSAGE, TOOL, AGENT, RETRIEVAL, GENERATION, ROUTER, SYSTEM, FEEDBACK", rule.TrustLens.Type)
			}
		}

		// Validate Mapping field if provided
		if rule.TrustLens.Mapping != nil {
			// Define valid data projection fields
			validDataProjectionFields := map[string]bool{
				"input":         true,
				"output":        true,
				"feedback_tag":  true,
				"feedback_text": true,
			}

			for key := range rule.TrustLens.Mapping.Input.DataProjection {
				if !validDataProjectionFields[key] {
					return fmt.Errorf("invalid data_projection field in input: %s. Must be one of: input, output, feedback_tag, feedback_text", key)
				}
			}

			for key := range rule.TrustLens.Mapping.Output.DataProjection {
				if !validDataProjectionFields[key] {
					return fmt.Errorf("invalid data_projection field in output: %s. Must be one of: input, output, feedback_tag, feedback_text", key)
				}
			}
		}
	}

	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}

	return nil
}
