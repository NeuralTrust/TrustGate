package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type getUpstreamHandler struct {
	logger         *logrus.Logger
	repo           *database.Repository
	cache          *cache.Cache
	upstreamFinder upstream.Finder
}

func NewGetUpstreamHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	upstreamFinder upstream.Finder,
) Handler {
	return &getUpstreamHandler{
		logger:         logger,
		repo:           repo,
		cache:          cache,
		upstreamFinder: upstreamFinder,
	}
}

// Handle @Summary Retrieve an Upstream by ID
// @Description Returns details of a specific upstream
// @Tags Upstreams
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Success 200 {object} upstream.Upstream "Upstream details"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [get]
func (s *getUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	// Try to get from cache first
	upstreamKey := fmt.Sprintf(cache.UpstreamKeyPattern, gatewayID, upstreamID)
	if upstreamJSON, err := s.cache.Get(c.Context(), upstreamKey); err == nil {
		var entity domain.Upstream
		if err := json.Unmarshal([]byte(upstreamJSON), &entity); err == nil {
			return c.Status(fiber.StatusOK).JSON(entity)
		}
	}

	// If not in cache, get from database
	entity, err := s.upstreamFinder.Find(c.Context(), gatewayID, upstreamID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "upstream not found"})
	}

	// Cache the upstream
	if err := s.cache.SaveUpstream(c.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache upstream")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
