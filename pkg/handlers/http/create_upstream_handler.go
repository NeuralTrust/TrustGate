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

type createUpstreamHandler struct {
	logger       *logrus.Logger
	creator      appUpstream.Creator
	auditService auditlogs.Service
}

func NewCreateUpstreamHandler(logger *logrus.Logger, creator appUpstream.Creator, auditService auditlogs.Service) Handler {
	return &createUpstreamHandler{
		logger:       logger,
		creator:      creator,
		auditService: auditService,
	}
}

// Handle @Summary Create a new Upstream
// @Description Adds a new upstream under a gateway
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream body request.UpstreamRequest true "Upstream data"
// @Success 201 {object} upstream.Upstream "Upstream created successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams [post]
func (h *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway uuid"})
	}

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	u, err := h.creator.Create(c.Context(), gatewayUUID, &req)
	if err != nil {
		if errors.Is(err, domain.ErrGatewayNotFound) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
		}
		if errors.Is(err, domain.ErrInvalidEmbeddingProvider) || errors.Is(err, domain.ErrValidation) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		h.logger.WithError(err).Error("failed to create upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	h.emitAuditLog(c, u.ID.String(), u.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusCreated).JSON(u)
}

func (h *createUpstreamHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeUpstreamCreated,
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
