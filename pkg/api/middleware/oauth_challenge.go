package middleware

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

// OAuthChallengeMiddleware implements the MCP authorization challenge: every
// 401 leaving the MCP plane carries a WWW-Authenticate header pointing at the
// RFC 9728 protected-resource metadata, so MCP clients can bootstrap the
// OAuth 2.1 discovery + authorization flow. It must wrap (run before) the
// Auth middleware.
type OAuthChallengeMiddleware struct{}

func NewOAuthChallengeMiddleware() *OAuthChallengeMiddleware {
	return &OAuthChallengeMiddleware{}
}

func (m *OAuthChallengeMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if isUnauthorized(c, err) {
			c.Set(fiber.HeaderWWWAuthenticate,
				`Bearer resource_metadata="`+c.BaseURL()+`/.well-known/oauth-protected-resource"`)
		}
		return err
	}
}

func isUnauthorized(c *fiber.Ctx, err error) bool {
	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code == fiber.StatusUnauthorized
	}
	return err == nil && c.Response().StatusCode() == fiber.StatusUnauthorized
}
