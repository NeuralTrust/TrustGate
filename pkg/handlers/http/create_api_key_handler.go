package http

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	ruledomain "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createAPIKeyHandler struct {
	logger          *logrus.Logger
	cache           *cache.Cache
	apiKeyRepo      domain.Repository
	ruleRepo        ruledomain.Repository
	policyValidator domain.PolicyValidator
	gatewayRepo     gateway.Repository
}

func NewCreateAPIKeyHandler(
	logger *logrus.Logger,
	cache *cache.Cache,
	apiKeyRepo domain.Repository,
	ruleRepo ruledomain.Repository,
	policyValidator domain.PolicyValidator,
	gatewayRepo gateway.Repository,
) Handler {
	return &createAPIKeyHandler{
		logger:          logger,
		cache:           cache,
		apiKeyRepo:      apiKeyRepo,
		ruleRepo:        ruleRepo,
		policyValidator: policyValidator,
		gatewayRepo:     gatewayRepo,
	}
}

// Handle @Summary Create a new API Key
// @Description Generates a new API key for the specified gateway
// @Tags API Keys
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param api_key body types.CreateAPIKeyRequest true "API Key request body"
// @Success 201 {object} apikey.APIKey "API Key created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/iam/api-key [post]
func (s *createAPIKeyHandler) Handle(c *fiber.Ctx) error {
	var req request.CreateAPIKeyRequest

	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	// Check if gateway_id is provided in the route (for gateway-scoped API keys)
	gatewayID := c.Params("gateway_id")
	if gatewayID != "" {
		// For gateway-scoped requests, set the subject_id from gateway_id
		req.SubjectID = gatewayID
		if req.SubjectType == "" {
			req.SubjectType = "gateway"
		}

		// Validate that gateway exists
		gatewayUUID, err := uuid.Parse(gatewayID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
		}

		_, err = s.gatewayRepo.Get(c.Context(), gatewayUUID)
		if err != nil {
			s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Gateway not found")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
		}
	}

	if err := req.Validate(); err != nil {
		s.logger.WithError(err).Error("request validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
	}

	var subjectUUID *uuid.UUID
	if req.SubjectID != "" {
		parsed, err := uuid.Parse(req.SubjectID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid subject ID"})
		}
		subjectUUID = &parsed
	}

	var subjectType domain.SubjectType
	if req.SubjectType == "" {
		subjectType = domain.GatewayType
	} else {
		subjectType, err = domain.SubjectFromString(req.SubjectType)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	if err := s.policyValidator.Validate(c.Context(), subjectType, subjectUUID, req.Policies); err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidPolicyIDFormat):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, domain.ErrFailedToValidatePolicy):
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, domain.ErrSubjectRequired):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		default:
			var missing *domain.MissingPoliciesError
			if errors.As(err, &missing) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "some policies do not exist"})
			}
			s.logger.WithError(err).Error("Policy validation failed")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	var policyUUIDs []uuid.UUID
	if len(req.Policies) > 0 {
		policyUUIDs = make([]uuid.UUID, 0, len(req.Policies))
		for _, policyID := range req.Policies {
			policyUUID, err := uuid.Parse(policyID)
			if err != nil {
				s.logger.WithError(err).WithField("policy_id", policyID).Error("invalid policy UUID format")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy UUID format"})
			}
			policyUUIDs = append(policyUUIDs, policyUUID)
		}
	}

	apiKey, err := domain.NewIAMApiKey(
		id,
		req.Name,
		s.generateAPIKey(),
		subjectType,
		subjectUUID,
		policyUUIDs,
		req.ExpiresAt,
	)

	if err != nil {
		s.logger.WithError(err).Error("failed to create IAM API key entity")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create API key"})
	}

	if err := s.apiKeyRepo.Create(c.Context(), apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to create API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create API key"})
	}

	if err := s.cache.SaveAPIKey(c.Context(), apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to cache API key")
	}

	// Create response with gateway_id field for compatibility with tests
	response := map[string]interface{}{
		"id":           apiKey.ID,
		"name":         apiKey.Name,
		"key":          apiKey.Key,
		"active":       apiKey.Active,
		"subject_type": apiKey.SubjectType,
		"policies":     apiKey.Policies,
		"expires_at":   apiKey.ExpiresAt,
		"created_at":   apiKey.CreatedAt,
	}

	// Add gateway_id field if subject is a gateway
	if apiKey.SubjectType == domain.GatewayType && apiKey.Subject != nil {
		response["gateway_id"] = apiKey.Subject.String()
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (s *createAPIKeyHandler) generateAPIKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString() // Fallback to UUID if crypto/rand fails
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
