package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type getGatewayHandler struct {
	logger             *logrus.Logger
	repo               *database.Repository
	transformer        *gateway.OutputTransformer
	getGatewayCache    gateway.GetGatewayCache
	updateGatewayCache gateway.UpdateGatewayCache
}

func NewGetGatewayHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	getGatewayCache gateway.GetGatewayCache,
	updateGatewayCache gateway.UpdateGatewayCache,
) Handler {
	return &getGatewayHandler{
		logger:             logger,
		repo:               repo,
		transformer:        gateway.NewOutputTransformer(),
		getGatewayCache:    getGatewayCache,
		updateGatewayCache: updateGatewayCache,
	}
}

// Handle @Summary Retrieve a Gateway by ID
// @Description Returns details of a specific gateway
// @Tags Gateways
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success      200 {object} gateway.Gateway "Gateway"
// @Failure 404 {object} map[string]interface{} "Gateway not found"
// @Router /api/v1/gateways/{gateway_id} [get]
func (s *getGatewayHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}
	// Add request details logging
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
		"method":     c.Method(),
		"path":       c.Path(),
		"user_agent": c.Get("User-Agent"),
		"referer":    c.Get("Referer"),
	}).Info("Gateway retrieval request received")

	// Add validation for gateway ID
	if gatewayID == "" || gatewayID == "null" {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
			"method":     c.Method(),
			"path":       c.Path(),
			"user_agent": c.Get("User-Agent"),
			"referer":    c.Get("Referer"),
		}).Error("Invalid gateway ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "gateway_id is required"})
	}

	// Validate UUID format
	if _, err := uuid.Parse(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("invalid gateway_id format")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id format"})
	}

	s.logger.WithField("gateway_id", gatewayID).Info("Getting gateway")

	// Try to get from cache first
	entity, err := s.getGatewayCache.Retrieve(c.Context(), gatewayID)
	if err != nil {
		// If not in cache, get from database
		dbGateway, err := s.repo.GetGateway(c.Context(), gatewayUUID)
		if err != nil {
			s.logger.WithError(err).Error("failed to get gateway")
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
		}

		// Convert to API type
		entity, err = s.transformer.Transform(dbGateway)
		if err != nil {
			s.logger.WithError(err).Error("failed to convert gateway")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to process gateway configuration"})
		}

		// Store in cache
		if err := s.updateGatewayCache.Update(c.Context(), dbGateway); err != nil {
			s.logger.WithError(err).Error("failed to cache gateway")
		}
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
