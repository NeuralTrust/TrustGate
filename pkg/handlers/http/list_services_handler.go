package http

import (
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type listServicesHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
}

func NewListServicesHandler(logger *logrus.Logger, repo *database.Repository) Handler {
	return &listServicesHandler{
		logger: logger,
		repo:   repo,
	}
}

func (s *listServicesHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	offset := 0
	limit := 10

	// Parse query parameters
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	// Fetch services from repository
	services, err := s.repo.ListServices(c.Context(), gatewayID, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list services")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(services)
}
