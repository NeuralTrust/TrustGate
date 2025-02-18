package middleware

import (
	"fmt"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

// Define constant keys for context values
const (
	GatewayIDKey = "gateway_id"
	ServiceIDKey = "service_id"
	RouteIDKey   = "route_id"
)

type MetricsMiddleware struct {
	logger *logrus.Logger
}

func NewMetricsMiddleware(logger *logrus.Logger) *MetricsMiddleware {
	return &MetricsMiddleware{
		logger: logger,
	}
}

func (m *MetricsMiddleware) MetricsMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get gateway ID from Fiber context
		gatewayID, ok := c.Locals(GatewayIDKey).(string)
		if !ok || gatewayID == "" {
			m.logger.Error("Gateway ID not found in context")
			return c.Next()
		}

		// Record connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
		}

		// Process request
		err := c.Next()

		// Always record request total
		status := GetStatusClass(strconv.Itoa(c.Response().StatusCode()))
		metrics.GatewayRequestTotal.WithLabelValues(
			gatewayID,
			c.Method(),
			status,
		).Inc()

		// Decrease connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
		}

		return err
	}
}

// GetStatusClass returns either the specific status code or its class (e.g., "2xx")
func GetStatusClass(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "5xx" // Return server error class if status code is invalid
	}
	return fmt.Sprintf("%dxx", code/100)
}
