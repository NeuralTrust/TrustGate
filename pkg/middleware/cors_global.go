package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

type corsGlobalMiddleware struct {
	allowOrigins     []string
	allowMethods     []string
	allowCredentials bool
	exposeHeaders    []string
	maxAge           string
}

func NewCORSGlobalMiddleware(
	allowOrigins []string,
	allowMethods []string,
	allowCredentials bool,
	exposeHeaders []string,
	maxAge string,
) Middleware {
	return &corsGlobalMiddleware{
		allowOrigins:     allowOrigins,
		allowMethods:     allowMethods,
		allowCredentials: allowCredentials,
		exposeHeaders:    exposeHeaders,
		maxAge:           maxAge,
	}
}

func (m *corsGlobalMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		if origin == "" {
			return c.Next()
		}

		allowed := false
		for _, o := range m.allowOrigins {
			if o == "*" || strings.EqualFold(o, origin) {
				allowed = true
				break
			}
		}
		if allowed {
			c.Set("Vary", "Origin")
			if m.allowCredentials {
				c.Set("Access-Control-Allow-Origin", origin)
				c.Set("Access-Control-Allow-Credentials", "true")
			} else {
				if hasStar(m.allowOrigins) {
					c.Set("Access-Control-Allow-Origin", "*")
				} else {
					c.Set("Access-Control-Allow-Origin", origin)
				}
			}
			if len(m.exposeHeaders) > 0 {
				c.Set("Access-Control-Expose-Headers", strings.Join(m.exposeHeaders, ", "))
			}

			if c.Method() == fiber.MethodOptions {
				if c.Get("X-TG-API-Key") == "" {
					reqMethod := c.Get("Access-Control-Request-Method")
					if reqMethod != "" {
						c.Set("Access-Control-Allow-Methods", strings.Join(m.allowMethods, ", "))
						reqHeaders := c.Get("Access-Control-Request-Headers")
						if reqHeaders != "" {
							c.Set("Access-Control-Allow-Headers", reqHeaders)
						} else {
							c.Set("Access-Control-Allow-Headers", "Content-Type")
						}
						if m.maxAge != "" {
							c.Set("Access-Control-Max-Age", m.maxAge)
						}
						return c.SendStatus(fiber.StatusNoContent)
					}
				}
			}
		}
		return c.Next()
	}
}

func hasStar(arr []string) bool {
	for _, v := range arr {
		if v == "*" {
			return true
		}
	}
	return false
}
