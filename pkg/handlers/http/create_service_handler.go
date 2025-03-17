package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type createServiceHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

// NewCreateServiceHandler @Summary Create a new Service
// @Description Adds a new service under a gateway
// @Tags Services
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param service body object true "Service request body"
// @Success 201 {object} service.Service "Service created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/gateways/{gateway_id}/services [post]
func NewCreateServiceHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &createServiceHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *createServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var service service.Service
	if err := c.BodyParser(&service); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	service.GatewayID = gatewayID

	if err := s.repo.CreateService(c.Context(), &service); err != nil {
		s.logger.WithError(err).Error("Failed to create service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the service
	if err := s.cache.SaveService(c.Context(), gatewayID, &service); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	return c.Status(fiber.StatusCreated).JSON(service)
}
