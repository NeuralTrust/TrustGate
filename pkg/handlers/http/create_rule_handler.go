package http

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createRuleHandler struct {
	logger       *logrus.Logger
	repo         *database.Repository
	validateRule *rule.ValidateRule
}

func NewCreateRuleHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	validateRule *rule.ValidateRule,
) Handler {
	return &createRuleHandler{
		logger:       logger,
		repo:         repo,
		validateRule: validateRule,
	}
}

func (s *createRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var req types.CreateRuleRequest
	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Validate the rule request
	if err := s.validateRule.Validate(&req); err != nil {
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

	// Create the database model
	dbRule := &models.ForwardingRule{
		ID:            uuid.NewString(),
		GatewayID:     gatewayID,
		Path:          req.Path,
		ServiceID:     req.ServiceID,
		Methods:       req.Methods,
		Headers:       models.HeadersJSON(req.Headers),
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		PluginChain:   req.PluginChain,
		Active:        true,
		Public:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Store in database
	if err := s.repo.CreateRule(c.Context(), dbRule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create rule"})
	}

	// Use existing helper to convert to API response
	response, err := s.getRuleResponse(dbRule)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rule response")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to process rule"})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (s *createRuleHandler) getRuleResponse(rule *models.ForwardingRule) (types.ForwardingRule, error) {
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

	// Convert headers from pq.StringArray to map[string]string
	headers := make(map[string]string)
	for _, h := range rule.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return types.ForwardingRule{
		ID:            rule.ID,
		GatewayID:     rule.GatewayID,
		Path:          rule.Path,
		ServiceID:     rule.ServiceID,
		Methods:       rule.Methods,
		Headers:       headers,
		StripPath:     rule.StripPath,
		PreserveHost:  rule.PreserveHost,
		RetryAttempts: rule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        rule.Active,
		Public:        rule.Public,
		CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
	}, nil
}
