package http

import (
	"errors"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateUpstreamHandler struct {
	logger       *logrus.Logger
	updater      appUpstream.Updater
	auditService auditlogs.Service
}

func NewUpdateUpstreamHandler(logger *logrus.Logger, updater appUpstream.Updater, auditService auditlogs.Service) Handler {
	return &updateUpstreamHandler{
		logger:       logger,
		updater:      updater,
		auditService: auditService,
	}
}

// Handle @Summary Update an Upstream
// @Description Updates an existing upstream
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Param upstream body request.UpstreamRequest true "Updated upstream data"
// @Success 200 {object} upstream.Upstream "Upstream updated successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [put]
func (h *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	upstreamUUID, err := uuid.Parse(c.Params("upstream_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	u, err := h.updater.Update(c.Context(), gatewayUUID, upstreamUUID, &req)
	if err != nil {
		if errors.Is(err, domain.ErrUpstreamNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "upstream not found"})
		}
		if errors.Is(err, domain.ErrInvalidEmbeddingProvider) || errors.Is(err, domain.ErrValidation) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		h.logger.WithError(err).Error("failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	h.emitAuditLog(c, u.ID.String(), u.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusOK).JSON(u)
}

func (h *updateUpstreamHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeUpstreamUpdated,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeUpstream,
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
