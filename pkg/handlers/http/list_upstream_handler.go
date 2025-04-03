package http

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type listUpstreamHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewListUpstreamHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &listUpstreamHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

// Handle @Summary Retrieve all Upstreams
// @Description Returns a list of all upstreams for a gateway
// @Tags Upstreams
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Success 200 {array} upstream.Upstream "List of upstreams"
// @Router /api/v1/gateways/{gateway_id}/upstreams [get]
func (s *listUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	offset := 0
	limit := 10

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	// Try to get from cache first
	upstreamsKey := fmt.Sprintf(cache.UpstreamsKeyPattern, gatewayID)
	if upstreamsJSON, err := s.cache.Get(c.Context(), upstreamsKey); err == nil {
		var upstreams []upstream.Upstream
		if err := json.Unmarshal([]byte(upstreamsJSON), &upstreams); err == nil {
			return c.Status(fiber.StatusOK).JSON(upstreams)
		}
	}

	// If not in cache, get from database
	upstreams, err := s.repo.ListUpstreams(c.Context(), gatewayUUID, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("failed to list upstreams")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Cache the results
	if upstreamsJSON, err := json.Marshal(upstreams); err == nil {
		if err := s.cache.Set(c.Context(), upstreamsKey, string(upstreamsJSON), 0); err != nil {
			s.logger.WithError(err).Error("failed to cache upstreams list")
		}
	}

	return c.Status(fiber.StatusOK).JSON(upstreams)
}
