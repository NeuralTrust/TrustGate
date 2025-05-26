package http

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createAPIKeyHandler struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	apiKeyRepo domain.Repository
}

func NewCreateAPIKeyHandler(logger *logrus.Logger, cache *cache.Cache, apiKeyRepo domain.Repository) Handler {
	return &createAPIKeyHandler{
		logger:     logger,
		cache:      cache,
		apiKeyRepo: apiKeyRepo,
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
// @Router /api/v1/gateways/{gateway_id}/keys [post]
func (s *createAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	var req types.CreateAPIKeyRequest

	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
	}

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	apiKey := &domain.APIKey{
		ID:        id,
		Name:      req.Name,
		GatewayID: gatewayUUID,
		Key:       s.generateAPIKey(),
	}

	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = *req.ExpiresAt
	}

	if err := s.apiKeyRepo.Create(c.Context(), apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to create API key")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create API key"})
	}

	// Save to cache
	if err := s.cache.SaveAPIKey(c.Context(), apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to cache API key")
		// Continue execution even if caching fails
	}

	return c.Status(fiber.StatusCreated).JSON(apiKey)
}

func (s *createAPIKeyHandler) generateAPIKey() string {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString() // Fallback to UUID if crypto/rand fails
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
