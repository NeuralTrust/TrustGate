package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
)

type ConfigSyncAuthMiddleware struct {
	tokenDigests [][32]byte
	logger       *slog.Logger
}

func NewConfigSyncAuthMiddleware(cfg *config.Config, logger *slog.Logger) *ConfigSyncAuthMiddleware {
	m := &ConfigSyncAuthMiddleware{logger: logger}
	if cfg.ConfigSync.Token != "" {
		m.tokenDigests = append(m.tokenDigests, sha256.Sum256([]byte(cfg.ConfigSync.Token)))
	}
	if cfg.ConfigSync.TokenPrevious != "" {
		m.tokenDigests = append(m.tokenDigests, sha256.Sum256([]byte(cfg.ConfigSync.TokenPrevious)))
	}
	if len(m.tokenDigests) == 0 && logger != nil {
		logger.Warn("config-sync token is not configured; the snapshot endpoint will reject every pull and no data plane can converge",
			slog.String("component", "configsnapshot"))
	}
	return m
}

func (m *ConfigSyncAuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(m.tokenDigests) == 0 {
			if m.logger != nil {
				m.logger.Warn("config-sync token is not configured; rejecting snapshot request",
					slog.String("component", "configsnapshot"))
			}
			return configSyncUnauthorized(c)
		}
		provided := configSyncBearerToken(c)
		if provided == "" {
			return configSyncUnauthorized(c)
		}
		providedDigest := sha256.Sum256([]byte(provided))
		matched := 0
		for i := range m.tokenDigests {
			matched |= subtle.ConstantTimeCompare(providedDigest[:], m.tokenDigests[i][:])
		}
		if matched != 1 {
			return configSyncUnauthorized(c)
		}
		return c.Next()
	}
}

func configSyncBearerToken(c *fiber.Ctx) string {
	header := c.Get(authorizationHeader)
	if !strings.HasPrefix(header, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
}

func configSyncUnauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or invalid config-sync token"})
}
