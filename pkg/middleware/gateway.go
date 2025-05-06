package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"

	"github.com/sirupsen/logrus"
)

type gatewayMiddleware struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	repo       *database.Repository
	dataFinder gateway.DataFinder
	baseDomain string
}

func NewGatewayMiddleware(
	logger *logrus.Logger,
	cache *cache.Cache,
	repo *database.Repository,
	dataFinder gateway.DataFinder,
	baseDomain string,
) Middleware {
	return &gatewayMiddleware{
		logger:     logger,
		cache:      cache,
		repo:       repo,
		dataFinder: dataFinder,
		baseDomain: baseDomain,
	}
}

func (m *gatewayMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Try to get host from different sources
		host := ctx.Get("Host")
		if host == "" {
			host = string(ctx.Request().Host())
		}

		// Skip middleware for system endpoints
		if strings.HasPrefix(ctx.Path(), "/__/") {
			return ctx.Next()
		}

		if host == "" {
			m.logger.Error("No host header found")
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Host header required"})
		}

		ctx.Locals(common.LatencyContextKey, time.Now())
		c := context.WithValue(ctx.Context(), common.LatencyContextKey, time.Now())
		ctx.SetUserContext(c)

		subdomain := m.extractSubdomain(host)
		if subdomain == "" {
			m.logger.WithFields(logrus.Fields{
				"host":       host,
				"baseDomain": m.baseDomain,
			}).Error("Failed to extract subdomain")
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid gateway identifier"})
		}

		// Try to get gateway ID from cache first
		key := fmt.Sprintf("subdomain:%s", subdomain)
		gatewayID, err := m.cache.Get(ctx.Context(), key)
		if err != nil {
			if err.Error() == "redis: nil" {
				// If not in cache, try to get from database
				m.logger.WithField("subdomain", subdomain).Debug("Cache miss, querying database")

				gatewayEntity, err := m.repo.GetGatewayBySubdomain(ctx.Context(), subdomain)
				if err != nil {
					m.logger.WithFields(logrus.Fields{
						"subdomain": subdomain,
						"error":     err,
						"errorType": fmt.Sprintf("%T", err),
						"host":      host,
					}).Error("Failed to get gateway from database")
					return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Gateway not found"})
				}

				gatewayID = gatewayEntity.ID.String()
				// Cache the gateway ID
				if err := m.cache.Set(ctx.Context(), key, gatewayID, 24*time.Hour); err != nil {
					m.logger.WithFields(logrus.Fields{
						"error":     err,
						"key":       key,
						"gatewayID": gatewayID,
					}).Error("Failed to cache gateway ID")
				}
			} else {
				m.logger.WithFields(logrus.Fields{
					"error": err,
					"key":   key,
				}).Error("Failed to get gateway ID from cache")
				return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
			}
		}

		gatewayData, err := m.dataFinder.Find(ctx.Context(), gatewayID)
		if err != nil {
			m.logger.WithError(err).Error("failed to fetch gateway data")
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch gateway data"})
		}

		ctx.Locals(common.GatewayContextKey, gatewayID)
		ctx.Locals(string(common.GatewayDataContextKey), gatewayData)

		c = context.WithValue(c, common.GatewayContextKey, gatewayID)
		c = context.WithValue(c, string(common.GatewayDataContextKey), gatewayData)

		ctx.SetUserContext(c)

		return ctx.Next()
	}
}

func (m *gatewayMiddleware) extractSubdomain(host string) string {
	m.logger.WithFields(logrus.Fields{
		"host":       host,
		"baseDomain": m.baseDomain,
	}).Debug("Extracting subdomain")

	// Remove port if present using strings.Split
	host = strings.Split(host, ":")[0]
	m.logger.WithFields(logrus.Fields{
		"host": host,
	}).Debug("Removed port from host")

	// Check if host ends with base domain
	suffix := "." + m.baseDomain
	if !strings.HasSuffix(host, suffix) {
		if strings.HasSuffix(host, m.baseDomain) {
			// If host matches base domain exactly without dot
			suffix = m.baseDomain
		} else {
			m.logger.WithFields(logrus.Fields{
				"host":       host,
				"baseDomain": m.baseDomain,
				"suffix":     suffix,
			}).Debug("Host does not match base domain")
			return ""
		}
	}

	// Extract subdomain by removing the base domain
	subdomain := strings.TrimSuffix(host, suffix)

	// Remove trailing dot if present
	subdomain = strings.TrimSuffix(subdomain, ".")

	if subdomain == "" {
		m.logger.WithFields(logrus.Fields{
			"host":   host,
			"suffix": suffix,
		}).Debug("No subdomain found")
		return ""
	}

	m.logger.WithFields(logrus.Fields{
		"host":      host,
		"subdomain": subdomain,
		"suffix":    suffix,
	}).Debug("Successfully extracted subdomain")

	return subdomain
}
