package http

import (
	"errors"

	ruledomain "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateAPIKeyPoliciesRequest struct {
	Policies []string `json:"policies"`
}

type UpdateAPIKeyPoliciesHandlerDeps struct {
	Logger          *logrus.Logger
	Cache           cache.Client
	ApiKeyRepo      domain.Repository
	RuleRepo        ruledomain.Repository
	PolicyValidator domain.PolicyValidator
	AuditService    auditlogs.Service
}

type updateAPIKeyPoliciesHandler struct {
	logger          *logrus.Logger
	cache           cache.Client
	apiKeyRepo      domain.Repository
	ruleRepo        ruledomain.Repository
	policyValidator domain.PolicyValidator
	auditService    auditlogs.Service
}

func NewUpdateAPIKeyPoliciesHandler(deps UpdateAPIKeyPoliciesHandlerDeps) Handler {
	return &updateAPIKeyPoliciesHandler{
		logger:          deps.Logger,
		cache:           deps.Cache,
		apiKeyRepo:      deps.ApiKeyRepo,
		ruleRepo:        deps.RuleRepo,
		policyValidator: deps.PolicyValidator,
		auditService:    deps.AuditService,
	}
}

// Handle @Summary Update API Key policies
// @Description Updates the set of allowed rule IDs (policies) for an API key
// @Tags API Keys
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param key_id path string true "API Key ID"
// @Param update body updateAPIKeyPoliciesRequest true "Policies update payload"
// @Success 200 {object} apikey.APIKey "API Key updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Failure 404 {object} map[string]interface{} "API key not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /api/v1/iam/api-key/{key_id}/policies [put]
func (h *updateAPIKeyPoliciesHandler) Handle(c *fiber.Ctx) error {
	keyIDParam := c.Params("key_id")
	subjectIDParam := c.Query("subject_id")

	var req updateAPIKeyPoliciesRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	keyID, err := uuid.Parse(keyIDParam)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid key ID"})
	}

	entity, err := h.apiKeyRepo.GetByID(c.Context(), keyID)
	if err != nil {
		h.logger.WithError(err).WithField("key_id", keyID).Error("failed to load api key")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "api key not found"})
	}

	// Validate subject if provided
	if subjectIDParam != "" {
		subjectID, err := uuid.Parse(subjectIDParam)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid subject ID"})
		}
		if entity.Subject != subjectID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "api key does not belong to subject"})
		}
	}

	// For policy validation, use the entity's subject or the provided subjectID
	var validationSubjectID uuid.UUID
	if subjectIDParam != "" {
		parsed, err := uuid.Parse(subjectIDParam)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid subject ID format"})
		}
		validationSubjectID = parsed
	} else {
		validationSubjectID = entity.Subject
	}

	if err := h.policyValidator.Validate(c.Context(), entity.SubjectType, validationSubjectID, req.Policies); err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidPolicyIDFormat):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, domain.ErrFailedToValidatePolicy):
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		case errors.Is(err, domain.ErrSubjectRequired):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		default:
			var missing *domain.MissingPoliciesError
			if errors.As(err, &missing) {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "some policies do not exist"})
			}
			h.logger.WithError(err).Error("Policy validation failed")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
	}

	var policyUUIDs []uuid.UUID
	if len(req.Policies) > 0 {
		policyUUIDs = make([]uuid.UUID, 0, len(req.Policies))
		for _, policyID := range req.Policies {
			policyUUID, err := uuid.Parse(policyID)
			if err != nil {
				h.logger.WithError(err).WithField("policy_id", policyID).Error("invalid policy UUID format")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy UUID format"})
			}
			policyUUIDs = append(policyUUIDs, policyUUID)
		}
	}

	entity.Policies = policyUUIDs
	if err := h.apiKeyRepo.Update(c.Context(), entity); err != nil {
		h.logger.WithError(err).Error("failed to update api key policies")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update api key"})
	}

	if err := h.cache.SaveAPIKey(c.Context(), entity); err != nil {
		h.logger.WithError(err).Warn("failed to cache updated api key")
	}

	h.emitAuditLog(c, entity.ID.String(), entity.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusOK).JSON(entity)
}

func (h *updateAPIKeyPoliciesHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if h.auditService == nil {
		return
	}
	h.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeAPIKeyPoliciesUpdated,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeAPIKey,
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
