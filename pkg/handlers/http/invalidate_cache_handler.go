package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type invalidateCacheHandler struct {
	logger *logrus.Logger
	cache  cache.Client
}

func NewInvalidateCacheHandler(
	logger *logrus.Logger,
	cache cache.Client,
) Handler {
	return &invalidateCacheHandler{
		logger: logger,
		cache:  cache,
	}
}

func (h *invalidateCacheHandler) Handle(c *fiber.Ctx) error {
	h.logger.Info("Invalidating cache")

	if err := h.cache.InvalidateAll(c.Context()); err != nil {
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
