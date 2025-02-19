package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// deleteUpstreamHandler struct
type deleteUpstreamHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
	cache  *cache.Cache
}

func NewDeleteUpstreamHandler(logger *logrus.Logger, repo *database.Repository, cache *cache.Cache) Handler {
	return &deleteUpstreamHandler{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (s *deleteUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	if err := s.repo.DeleteUpstream(c.Context(), upstreamID); err != nil {
		if strings.Contains(err.Error(), "being used by") {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		s.logger.WithError(err).Error("Failed to delete upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	upstreamKey := fmt.Sprintf(cache.UpstreamKeyPattern, gatewayID, upstreamID)
	upstreamsKey := fmt.Sprintf(cache.UpstreamsKeyPattern, gatewayID)
	if err := s.cache.Delete(c.Context(), upstreamKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate upstream cache")
	}
	if err := s.cache.Delete(c.Context(), upstreamsKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate upstreams list cache")
	}

	return c.SendStatus(http.StatusNoContent)
}
