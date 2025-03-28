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

// Handle @Summary Retrieve all Services
// @Description Returns a list of all services for a gateway
// @Tags Services
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success 200 {array} service.Service "List of services"
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/gateways/{gateway_id}/services [get]
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
		s.logger.WithError(err).Error("failed to list services")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusOK).JSON(services)
}
