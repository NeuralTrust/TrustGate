package http

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger             *logrus.Logger
	repo               domain.Repository
	updateGatewayCache gateway.UpdateGatewayCache
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	repo domain.Repository,
	updateGatewayCache gateway.UpdateGatewayCache,
) Handler {
	return &createGatewayHandler{
		logger:             logger,
		repo:               repo,
		updateGatewayCache: updateGatewayCache,
	}
}

func (h *createGatewayHandler) Handle(c *fiber.Ctx) error {
	var entity domain.Gateway

	if err := c.BodyParser(&entity); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	now := time.Now()
	entity.CreatedAt = now
	entity.UpdatedAt = now

	if err := h.repo.Save(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to create gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := h.updateGatewayCache.Update(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to update gateway cache")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}
