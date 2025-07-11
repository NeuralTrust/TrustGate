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

	client := h.cache.Client()

	if err := client.FlushAll(c.Context()).Err(); err != nil {
		h.logger.WithError(err).Error("failed to invalidate cache")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to invalidate cache",
		})
	}

	h.logger.Info("cache invalidated successfully")
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "cache invalidated successfully",
	})
}
