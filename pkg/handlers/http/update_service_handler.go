package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateServiceHandler struct {
	logger       *logrus.Logger
	repo         service.Repository
	publisher    infraCache.EventPublisher
	auditService auditlogs.Service
}

func NewUpdateServiceHandler(logger *logrus.Logger, repo service.Repository, publisher infraCache.EventPublisher, auditService auditlogs.Service) Handler {
	return &updateServiceHandler{
		logger:       logger,
		repo:         repo,
		publisher:    publisher,
		auditService: auditService,
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
// @Param service body request.ServiceRequest true "Updated service data"
// @Success 200 {object} service.Service "Service updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Service not found"
// @Router /api/v1/gateways/{gateway_id}/services/{service_id} [put]
func (s *updateServiceHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	serviceID := c.Params("service_id")

	var req req.ServiceRequest
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
	// First get the existing service to preserve CreatedAt
	existingService, err := s.repo.Get(c.Context(), serviceID)
	if err != nil {
		s.logger.WithError(err).Error("failed to get existing service")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "service not found"})
	}

	// Update the entity with new values while preserving CreatedAt
	// UpdatedAt will be handled automatically by the BeforeUpdate hook
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
		CreatedAt:   existingService.CreatedAt, // Preserve original CreatedAt
		// UpdatedAt will be set by BeforeUpdate hook
	}

	if err := s.repo.Update(c.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("failed to update service")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the updated service
	err = s.publisher.Publish(
		c.Context(),
		event.UpdateServiceCacheEvent{
			ServiceID: entity.ID.String(),
			GatewayID: entity.GatewayID.String(),
		},
	)
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update service cache event")
	}

	s.emitAuditLog(c, entity.ID.String(), entity.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusOK).JSON(entity)
}

func (s *updateServiceHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeServiceUpdated,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeService,
			ID:   targetID,
			Name: targetName,
		},
		Context: auditlogs.Context{
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Request-ID"),
		},
	})
}
