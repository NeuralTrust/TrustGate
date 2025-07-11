package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type invalidateCacheHandler struct {
	logger *logrus.Logger
	cache  *cache.Cache
}

func NewInvalidateCacheHandler(
	logger *logrus.Logger,
	cache *cache.Cache,
) Handler {
	return &invalidateCacheHandler{
		logger: logger,
		cache:  cache,
	}
}

func (h *invalidateCacheHandler) Handle(c *fiber.Ctx) error {
	h.logger.Info("Invalidating cache")

	// Get the Redis client from the cache
	client := h.cache.Client()

	// Execute FlushDB command to clear only the current database
	if err := client.FlushDB(c.Context()).Err(); err != nil {
		h.logger.WithError(err).Error("Failed to invalidate cache")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to invalidate cache",
		})
	}

	h.logger.Info("Cache invalidated successfully")
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Cache invalidated successfully",
	})
}
