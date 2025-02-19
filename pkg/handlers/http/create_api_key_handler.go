package http

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createAPIKeyHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewCreateAPIKeyHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &createAPIKeyHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *createAPIKeyHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	var req types.CreateAPIKeyRequest

	if err := c.BodyParser(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Generate new API key
	apiKey := &models.APIKey{
		ID:        uuid.NewString(),
		Name:      req.Name,
		GatewayID: gatewayID,
		Key:       s.generateAPIKey(),
	}

	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = *req.ExpiresAt
	}

	if err := s.repo.CreateAPIKey(c.Context(), apiKey); err != nil {
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
