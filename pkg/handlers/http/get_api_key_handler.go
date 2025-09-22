package http

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type getAPIKeyHandler struct {
	logger *logrus.Logger
	cache  *cache.Cache
	repo   apikey.Repository
}

func NewGetAPIKeyHandler(logger *logrus.Logger, cache *cache.Cache, repo apikey.Repository) Handler {
	return &getAPIKeyHandler{
		logger: logger,
		cache:  cache,
		repo:   repo,
	}
}

func (s *getAPIKeyHandler) Handle(c *fiber.Ctx) error {
	keyID := c.Params("key_id")
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid key_id"})
	}

	apiKey, err := s.repo.GetByID(c.Context(), keyUUID)
	if err != nil {
		if errors.Is(err, domain.ErrEntityNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "API Key not found"})
		}
		s.logger.WithError(err).Error("failed to get API Key from database")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to get API Key"})
	}

	return c.Status(fiber.StatusOK).JSON(apiKey)
}
