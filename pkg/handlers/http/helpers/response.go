package helpers

import (
	"fmt"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func PrepareResponse(c *fiber.Ctx, logger *logrus.Logger) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		logger.Error("failed to get stream mode channel")
		return fmt.Errorf("failed to get stream mode channel")
	}
	select {
	case streamMode <- false:
		logger.Debug("stream mode disabled")
	default:
	}

	if traceId, ok := c.Locals(common.TraceIdKey).(string); ok && traceId != "" {
		c.Set("X-Trace-ID", traceId)
	}
	return nil
}

func SendErrorResponse(c *fiber.Ctx, logger *logrus.Logger, status int, message fiber.Map) error {
	if err := PrepareResponse(c, logger); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(status).JSON(message)
}

func SendSuccessResponse(c *fiber.Ctx, logger *logrus.Logger, status int, body []byte) error {
	if err := PrepareResponse(c, logger); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(status).Send(body)
}

func SendSuccessJSONResponse(c *fiber.Ctx, logger *logrus.Logger, status int, body interface{}) error {
	if err := PrepareResponse(c, logger); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(status).JSON(body)
}
