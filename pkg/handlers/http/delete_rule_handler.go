package http

import (
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type DeleteRuleHandlerDeps struct {
	Logger       *logrus.Logger
	Repo         forwarding_rule.Repository
	Cache        cache.Client
	Publisher    cache.EventPublisher
	AuditService auditlogs.Service
}

type deleteRuleHandler struct {
	logger       *logrus.Logger
	repo         forwarding_rule.Repository
	cache        cache.Client
	publisher    cache.EventPublisher
	auditService auditlogs.Service
}

func NewDeleteRuleHandler(deps DeleteRuleHandlerDeps) Handler {
	return &deleteRuleHandler{
		logger:       deps.Logger,
		repo:         deps.Repo,
		cache:        deps.Cache,
		publisher:    deps.Publisher,
		auditService: deps.AuditService,
	}
}

// Handle @Summary Delete a Rule
// @Description Removes a rule from a gateway
// @Tags Rules
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param rule_id path string true "Rule ID"
// @Success 204 "Rule deleted successfully"
// @Failure 404 {object} map[string]interface{} "Rule not found"
// @Router /api/v1/gateways/{gateway_id}/rules/{rule_id} [delete]
func (s *deleteRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	ruleID := c.Params("rule_id")
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway_id"})
	}
	ruleUUID, err := uuid.Parse(c.Params("rule_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid rule_id"})
	}
	err = s.repo.Delete(c.Context(), ruleUUID, gatewayUUID)
	if err != nil {
		if errors.Is(err, repository.ErrRuleNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(
				fiber.Map{
					"error": fmt.Sprintf("rule not found with id %s and gateway %s", ruleID, gatewayID),
				},
			)
		}
		s.logger.WithError(err).Error("failed to delete rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete rule"})
	}

	// Invalidate cache after deletion
	if err := s.publisher.Publish(
		c.Context(),
		event.DeleteRulesCacheEvent{GatewayID: gatewayID, RuleID: ruleID},
	); err != nil {
		s.logger.WithError(err).Error("failed to publish cache invalidation")
	}

	s.emitAuditLog(c, ruleID, "", auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (s *deleteRuleHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeRuleDeleted,
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
