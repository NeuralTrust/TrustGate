package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type panicRecoverMiddleware struct {
	logger *logrus.Logger
}

func NewPanicRecoverMiddleware(logger *logrus.Logger) Middleware {
	return &panicRecoverMiddleware{logger: logger}
}

func (m *panicRecoverMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				m.logger.WithFields(logrus.Fields{
					"error": r,
					"path":  c.Path(),
				}).Error("HTTP server panic recovered")

				if c.Response().Header.StatusCode() == 0 {
					if err := c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Internal server error",
					}); err != nil {
						m.logger.WithError(err).Error("failed to write panic recovery response")
					}
				}
			}
		}()

		return c.Next()
	}
}
