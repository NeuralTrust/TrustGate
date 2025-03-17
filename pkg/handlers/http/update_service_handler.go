package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type updateServiceHandler struct {
	logger    *logrus.Logger
	repo      *database.Repository
	publisher infraCache.EventPublisher
}

func NewUpdateServiceHandler(logger *logrus.Logger, repo *database.Repository, publisher infraCache.EventPublisher) Handler {
	return &updateServiceHandler{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

// Handle @Summary Update a Service
// @Description Updates an existing service
// @Tags Services
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param service_id path string true "Service ID"
// @Param service body object true "Updated service data"
// @Success 200 {object} service.Service "Service updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Service not found"
// @Router /api/v1/gateways/{gateway_id}/services/{service_id} [put]
func (s *updateServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	var entity service.Service
	if err := c.BodyParser(&entity); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Ensure IDs match
	entity.ID = serviceID
	entity.GatewayID = gatewayID

	if err := s.repo.UpdateService(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to update service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the updated service
	err := s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateServiceCacheEvent{
		ServiceID: entity.ID,
		GatewayID: entity.GatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update service cache event")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
