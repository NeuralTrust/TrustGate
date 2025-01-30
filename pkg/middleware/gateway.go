package middleware

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type GatewayMiddleware struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	repo       *database.Repository
	baseDomain string
}

func NewGatewayMiddleware(logger *logrus.Logger, cache *cache.Cache, repo *database.Repository, baseDomain string) *GatewayMiddleware {
	return &GatewayMiddleware{
		logger:     logger,
		cache:      cache,
		repo:       repo,
		baseDomain: baseDomain,
	}
}

func (m *GatewayMiddleware) IdentifyGateway() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get host from different sources
		host := c.GetHeader("Host")
		if host == "" {
			host = c.Request.Host
		}

		// Skip middleware for system endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/__/") {
			c.Next()
			return
		}

		if host == "" {
			m.logger.Error("No host header found")
			c.JSON(400, gin.H{"error": "Host header required"})
			c.Abort()
			return
		}

		m.logger.WithFields(logrus.Fields{
			"host":        host,
			"baseDomain":  m.baseDomain,
			"requestPath": c.Request.URL.Path,
			"method":      c.Request.Method,
		}).Debug("Looking up gateway by subdomain")

		subdomain := m.extractSubdomain(host)
		if subdomain == "" {
			m.logger.WithFields(logrus.Fields{
				"host":       host,
				"baseDomain": m.baseDomain,
			}).Error("Failed to extract subdomain")
			c.JSON(400, gin.H{"error": "Invalid gateway identifier"})
			c.Abort()
			return
		}

		// Add more detailed debug logging
		m.logger.WithFields(logrus.Fields{
			"subdomain":   subdomain,
			"host":        host,
			"baseDomain":  m.baseDomain,
			"requestPath": c.Request.URL.Path,
			"method":      c.Request.Method,
		}).Debug("Looking up gateway by subdomain")

		// Try to get gateway ID from cache first
		key := fmt.Sprintf("subdomain:%s", subdomain)
		gatewayID, err := m.cache.Get(c, key)
		if err != nil {
			if err.Error() == "redis: nil" {
				// If not in cache, try to get from database
				m.logger.WithField("subdomain", subdomain).Debug("Cache miss, querying database")

				gateway, err := m.repo.GetGatewayBySubdomain(c.Request.Context(), subdomain)
				if err != nil {
					m.logger.WithFields(logrus.Fields{
						"subdomain": subdomain,
						"error":     err,
						"errorType": fmt.Sprintf("%T", err),
						"host":      host,
					}).Error("Failed to get gateway from database")
					c.JSON(404, gin.H{"error": "Gateway not found"})
					c.Abort()
					return
				}

				gatewayID = gateway.ID
				// Cache the gateway ID
				if err := m.cache.Set(c.Request.Context(), key, gateway.ID, 24*time.Hour); err != nil {
					m.logger.WithFields(logrus.Fields{
						"error":     err,
						"key":       key,
						"gatewayID": gateway.ID,
					}).Error("Failed to cache gateway ID")
				}
			} else {
				m.logger.WithFields(logrus.Fields{
					"error": err,
					"key":   key,
				}).Error("Failed to get gateway ID from cache")
				c.JSON(500, gin.H{"error": "Internal server error"})
				c.Abort()
				return
			}
		}

		// Log successful gateway identification
		m.logger.WithFields(logrus.Fields{
			"subdomain": subdomain,
			"gatewayID": gatewayID,
			"path":      c.Request.URL.Path,
		}).Debug("Successfully identified gateway")

		// Set gateway ID in both gin context and request context
		c.Set(GatewayContextKey, gatewayID)
		ctx := context.WithValue(c.Request.Context(), common.GatewayContextKey, gatewayID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

func (m *GatewayMiddleware) extractSubdomain(host string) string {
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
