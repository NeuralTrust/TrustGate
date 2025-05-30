package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateServiceHandler struct {
	logger    *logrus.Logger
	repo      service.Repository
	publisher infraCache.EventPublisher
}

func NewUpdateServiceHandler(logger *logrus.Logger, repo service.Repository, publisher infraCache.EventPublisher) Handler {
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
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param service_id path string true "Service ID"
// @Param service body types.ServiceRequest true "Updated service data"
// @Success 200 {object} service.Service "Service updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Service not found"
// @Router /api/v1/gateways/{gateway_id}/services/{service_id} [put]
func (s *updateServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	var req types.ServiceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}
	id, err := uuid.Parse(serviceID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid service ID"})
	}
	upstreamId, err := uuid.Parse(req.UpstreamID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}
	entity := service.Service{
		ID:          id,
		GatewayID:   gatewayUUID,
		Name:        req.Name,
		Type:        req.Type,
		Description: req.Description,
		Tags:        req.Tags,
		UpstreamID:  upstreamId,
		Host:        req.Host,
		Port:        req.Port,
		Protocol:    req.Protocol,
		Path:        req.Path,
		Headers:     req.Headers,
		Credentials: req.Credentials,
		Retries:     req.Retries,
		CreatedAt:   req.CreatedAt,
		UpdatedAt:   req.UpdatedAt,
	}

	if err := s.repo.Update(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("failed to update service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the updated service
	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateServiceCacheEvent{
		ServiceID: entity.ID.String(),
		GatewayID: entity.GatewayID.String(),
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update service cache event")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
