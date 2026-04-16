package http

import (
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	req "github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/response"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createRuleHandler struct {
	logger       *logrus.Logger
	creator      rule.Creator
	auditService auditlogs.Service
}

func NewCreateRuleHandler(logger *logrus.Logger, creator rule.Creator, auditService auditlogs.Service) Handler {
	return &createRuleHandler{
		logger:       logger,
		creator:      creator,
		auditService: auditService,
	}
}

// Handle @Summary Create a new Rule
// @Description Adds a new rule under a gateway
// @Tags Rules
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "GatewayDTO ID"
// @Param rule body req.CreateRuleRequest true "Rule request body"
// @Success 201 {object} forwarding_rule.ForwardingRule "Rule created successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/gateways/{gateway_id}/rules [post]
func (h *createRuleHandler) Handle(c *fiber.Ctx) error {
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	var request req.CreateRuleRequest
	if err := c.BodyParser(&request); err != nil {
		h.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := request.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	r, err := h.creator.Create(c.Context(), gatewayUUID, &request)
	if err != nil {
		if errors.Is(err, domain.ErrGatewayNotFound) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
		}
		if errors.Is(err, domain.ErrServiceNotFound) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Service not found"})
		}
		if errors.Is(err, domain.ErrRuleAlreadyExists) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		if errors.Is(err, domain.ErrValidation) || errors.Is(err, domain.ErrInvalidRuleType) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		h.logger.WithError(err).Error("failed to create rule")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create rule"})
	}

	ruleOutput := getRuleResponse(r)

	h.emitAuditLog(c, r.ID.String(), r.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusCreated).JSON(ruleOutput)
}

func (h *createRuleHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeRuleCreated,
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

func getRuleResponse(r *forwarding_rule.ForwardingRule) response.ForwardingRuleOutput {
	outputPath := types.FlexiblePath{Primary: r.Path}
	if len(r.Paths) > 0 {
		outputPath.All = r.Paths
	}

	return response.ForwardingRuleOutput{
		ID:            r.ID.String(),
		Name:          r.Name,
		GatewayID:     r.GatewayID.String(),
		ServiceID:     r.ServiceID.String(),
		Path:          outputPath,
		Type:          string(r.Type),
		Methods:       r.Methods,
		Headers:       r.Headers,
		StripPath:     r.StripPath,
		PreserveHost:  r.PreserveHost,
		RetryAttempts: r.RetryAttempts,
		PluginChain:   r.PluginChain,
		Active:        r.Active,
		TrustLens:     r.TrustLens,
		SessionConfig: r.SessionConfig,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}
