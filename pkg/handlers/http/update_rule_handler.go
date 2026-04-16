package http

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateRuleHandler struct {
	logger       *logrus.Logger
	updater      rule.Updater
	auditService auditlogs.Service
}

func NewUpdateRuleHandler(logger *logrus.Logger, updater rule.Updater, auditService auditlogs.Service) Handler {
	return &updateRuleHandler{
		logger:       logger,
		updater:      updater,
		auditService: auditService,
	}
}

// Handle @Summary Update a Rule
// @Description Updates an existing rule
// @Tags Rules
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "GatewayDTO ID"
// @Param rule_id path string true "Rule ID"
// @Param rule body req.UpdateRuleRequest true "Updated rule data"
// @Success 204 "Rule updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "Rule not found"
// @Router /api/v1/gateways/{gateway_id}/rules/{rule_id} [put]
func (h *updateRuleHandler) Handle(c *fiber.Ctx) error {
	var updateReq req.UpdateRuleRequest
	if err := c.BodyParser(&updateReq); err != nil {
		h.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := updateReq.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}

	ruleUUID, err := uuid.Parse(c.Params("rule_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule_id"})
	}

	if err := h.updater.Update(c.Context(), gatewayUUID, ruleUUID, &updateReq); err != nil {
		if domain.IsNotFoundError(err) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "rule not found"})
		}
		if errors.Is(err, domain.ErrRuleAlreadyExists) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, domain.ErrInvalidRuleType) || errors.Is(err, domain.ErrValidation) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		h.logger.WithError(err).Error("failed to update rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update rule"})
	}

	h.emitAuditLog(c, c.Params("rule_id"), "", auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (h *updateRuleHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeRuleUpdated,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeRule,
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
