package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createServiceHandler struct {
	logger *logrus.Logger
	repo   service.Repository
	cache  cache.Client
}

// NewCreateServiceHandler @Summary Create a new Service
// @Description Adds a new service under a gateway
// @Tags Services
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param service body request.ServiceRequest true "Service request body"
// @Success 201 {object} service.Service "Service created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/gateways/{gateway_id}/services [post]
func NewCreateServiceHandler(logger *logrus.Logger, repo service.Repository, cache cache.Client) Handler {
	return &createServiceHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *createServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var r req.ServiceRequest
	if err := c.BodyParser(&r); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	upstreamId, err := uuid.Parse(r.UpstreamID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to parse upstream ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid upstream ID"})
	}
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid gateway ID"})
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
	}
	entity := service.Service{
		ID:          id,
		GatewayID:   gatewayUUID,
		Name:        r.Name,
		Type:        r.Type,
		Description: r.Description,
		Tags:        r.Tags,
		UpstreamID:  upstreamId,
		Host:        r.Host,
		Port:        r.Port,
		Protocol:    r.Protocol,
		Path:        r.Path,
		Headers:     r.Headers,
		Credentials: r.Credentials,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}

	if err := s.repo.Create(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to create service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the service
	if err := s.cache.SaveService(c.Context(), gatewayID, &entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}
