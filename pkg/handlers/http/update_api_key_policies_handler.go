package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	ruledomain "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateAPIKeyPoliciesRequest struct {
	Policies []string `json:"policies"`
}

type updateAPIKeyPoliciesHandler struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	apiKeyRepo domain.Repository
	ruleRepo   ruledomain.Repository
}

func NewUpdateAPIKeyPoliciesHandler(
	logger *logrus.Logger,
	cache *cache.Cache,
	apiKeyRepo domain.Repository,
	ruleRepo ruledomain.Repository,
) Handler {
	return &updateAPIKeyPoliciesHandler{
		logger:     logger,
		cache:      cache,
		apiKeyRepo: apiKeyRepo,
		ruleRepo:   ruleRepo,
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
// @Router /api/v1/gateways/{gateway_id}/keys/{key_id}/policies [put]
func (h *updateAPIKeyPoliciesHandler) Handle(c *fiber.Ctx) error {
	gatewayIDParam := c.Params("gateway_id")
	keyIDParam := c.Params("key_id")

	var req updateAPIKeyPoliciesRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	gatewayID, err := uuid.Parse(gatewayIDParam)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
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
	if entity.GatewayID != gatewayID {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "api key does not belong to gateway"})
	}

	var policyUUIDs []uuid.UUID
	if len(req.Policies) > 0 {
		policyUUIDs = make([]uuid.UUID, 0, len(req.Policies))
		for _, pid := range req.Policies {
			u, err := uuid.Parse(pid)
			if err != nil {
				h.logger.WithError(err).WithField("policy_id", pid).Error("invalid policy ID format")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid policy ID format"})
			}
			policyUUIDs = append(policyUUIDs, u)
		}

		existingRules, err := h.ruleRepo.FindByIds(c.Context(), policyUUIDs, gatewayID)
		if err != nil {
			h.logger.WithError(err).Error("failed to validate policies")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to validate policies"})
		}
		if len(existingRules) != len(policyUUIDs) {
			existing := make(map[uuid.UUID]bool)
			for _, r := range existingRules {
				existing[r.ID] = true
			}
			missing := make([]string, 0)
			for _, u := range policyUUIDs {
				if !existing[u] {
					missing = append(missing, u.String())
				}
			}
			h.logger.WithField("missing_policies", missing).Error("some policies do not exist")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "some policies do not exist", "missing_policies": missing})
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

	return c.Status(fiber.StatusOK).JSON(entity)
}
