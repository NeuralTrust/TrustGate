package middleware

import (
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/gofiber/fiber/v2"
)

type CORSMiddleware struct {
	allowOrigins     []string
	allowMethods     []string
	allowHeaders     []string
	exposeHeaders    []string
	allowCredentials bool
	maxAge           string
}

func NewCORSMiddleware(cfg *config.Config) *CORSMiddleware {
	return &CORSMiddleware{
		allowOrigins:     cfg.CORS.AllowOrigins,
		allowMethods:     cfg.CORS.AllowMethods,
		allowHeaders:     cfg.CORS.AllowHeaders,
		exposeHeaders:    cfg.CORS.ExposeHeaders,
		allowCredentials: cfg.CORS.AllowCredentials,
		maxAge:           cfg.CORS.MaxAge,
	}
}

func (m *CORSMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		if origin == "" {
			return c.Next()
		}

		if !m.originAllowed(origin) {
			return c.Next()
		}

		c.Set("Vary", "Origin")
		switch {
		case m.allowCredentials:
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Credentials", "true")
		case hasStar(m.allowOrigins):
			c.Set("Access-Control-Allow-Origin", "*")
		default:
			c.Set("Access-Control-Allow-Origin", origin)
		}

		if len(m.exposeHeaders) > 0 {
			c.Set("Access-Control-Expose-Headers", strings.Join(m.exposeHeaders, ", "))
		}

		if c.Method() == fiber.MethodOptions {
			if reqMethod := c.Get("Access-Control-Request-Method"); reqMethod != "" {
				c.Set("Access-Control-Allow-Methods", strings.Join(m.allowMethods, ", "))
				if reqHeaders := c.Get("Access-Control-Request-Headers"); reqHeaders != "" {
					c.Set("Access-Control-Allow-Headers", reqHeaders)
				} else if len(m.allowHeaders) > 0 {
					c.Set("Access-Control-Allow-Headers", strings.Join(m.allowHeaders, ", "))
				}
				if m.maxAge != "" {
					c.Set("Access-Control-Max-Age", m.maxAge)
				}
				return c.SendStatus(fiber.StatusNoContent)
			}
		}
		return c.Next()
	}
}

func (m *CORSMiddleware) originAllowed(origin string) bool {
	for _, o := range m.allowOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

func hasStar(arr []string) bool {
	for _, v := range arr {
		if v == "*" {
			return true
		}
	}
	return false
}
