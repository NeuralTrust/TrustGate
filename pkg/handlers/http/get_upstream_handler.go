package http

import (
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
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

func (s *getUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	// Try to get from cache first
	upstreamKey := fmt.Sprintf(cache.UpstreamKeyPattern, gatewayID, upstreamID)
	if upstreamJSON, err := s.cache.Get(c.Context(), upstreamKey); err == nil {
		var entity models.Upstream
		if err := json.Unmarshal([]byte(upstreamJSON), &entity); err == nil {
			return c.Status(fiber.StatusOK).JSON(entity)
		}
	}

	// If not in cache, get from database
	entity, err := s.upstreamFinder.Find(c.Context(), gatewayID, upstreamID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Upstream not found"})
	}

	// Cache the upstream
	if err := s.cache.SaveUpstream(c.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	return c.Status(fiber.StatusOK).JSON(entity)
}
