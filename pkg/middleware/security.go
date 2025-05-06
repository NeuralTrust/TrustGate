package middleware

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type securityMiddleware struct {
	logger *logrus.Logger
}

func NewSecurityMiddleware(
	logger *logrus.Logger,
) Middleware {
	return &securityMiddleware{
		logger: logger,
	}
}

func (m *securityMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayID, ok := c.Locals(common.GatewayContextKey).(string)
		if !ok || gatewayID == "" {
			m.logger.Error("gateway ID not found in context")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "gateway ID not found in context"})
		}

		gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
		if !ok {
			m.logger.
				WithField("gatewayID", gatewayID).
				Error("gateway data not found in context (security middleware)")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "gateway data not found in context (security middleware)"})
		}

		cfg := gatewayData.Gateway.SecurityConfig
		if cfg == nil {
			return c.Next()
		}
		// Allowed hosts
		if !cfg.IsDevelopment && len(cfg.AllowedHosts) > 0 {
			host := c.Hostname()
			allowed := false
			for _, h := range cfg.AllowedHosts {
				if cfg.AllowedHostsAreRegex {
					matched, err := regexp.MatchString(h, host)
					if err != nil {
						m.logger.
							WithField("pattern", h).
							WithError(err).
							Warn("invalid regex in allowed_hosts")
						continue
					}
					if matched {
						allowed = true
						break
					}
				} else {
					if h == host {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden: host not allowed"})
			}
		}

		// HTTPS detection based on headers and protocol
		isHTTPS := c.Protocol() == "https"
		if !isHTTPS && len(cfg.SSLProxyHeaders) > 0 {
			for header, expected := range cfg.SSLProxyHeaders {
				if strings.EqualFold(c.Get(header), expected) {
					isHTTPS = true
					break
				}
			}
		}

		// Redirect to HTTPS if not secure
		if !isHTTPS && cfg.SSLRedirect && !cfg.IsDevelopment {
			url := "https://" + cfg.SSLHost + c.OriginalURL()
			return c.Redirect(url, fiber.StatusMovedPermanently)
		}

		// Strict-Transport-Security
		if cfg.STSSeconds > 0 && isHTTPS {
			h := "max-age=" + strconv.Itoa(cfg.STSSeconds)
			if cfg.STSIncludeSubdomains {
				h += "; includeSubDomains"
			}
			c.Set("Strict-Transport-Security", h)
		}

		// X-Frame-Options
		if cfg.FrameDeny {
			if cfg.CustomFrameOptionsValue != "" {
				c.Set("X-Frame-Options", cfg.CustomFrameOptionsValue)
			} else {
				c.Set("X-Frame-Options", "DENY")
			}
		}

		// X-Content-Type-Options
		if cfg.ContentTypeNosniff {
			c.Set("X-Content-Type-Options", "nosniff")
		}

		// X-XSS-Protection
		if cfg.BrowserXSSFilter {
			c.Set("X-XSS-Protection", "1; mode=block")
		}

		// Referrer-Policy
		if cfg.ReferrerPolicy != "" {
			c.Set("Referrer-Policy", cfg.ReferrerPolicy)
		}

		// Content-Security-Policy
		if cfg.ContentSecurityPolicy != "" {
			c.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
		}

		return c.Next()
	}
}
