package middleware

import (
	"fmt"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/gofiber/fiber/v2"

	"github.com/sirupsen/logrus"
)

const (
	GatewayIDKey = "gateway_id"
	ServiceIDKey = "service_id"
	RouteIDKey   = "route_id"
)

type metricsMiddleware struct {
	logger *logrus.Logger
}

func NewMetricsMiddleware(logger *logrus.Logger) Middleware {
	return &metricsMiddleware{
		logger: logger,
	}
}

func (m *metricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayID, ok := c.Locals(common.GatewayContextKey).(string)
		if !ok || gatewayID == "" {
			m.logger.Error("Gateway ID not found in context")
			return c.Next()
		}

		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
		}

		err := c.Next()

		// Always record request total
		status := m.getStatusClass(strconv.Itoa(c.Response().StatusCode()))
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
func (m *metricsMiddleware) getStatusClass(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "5xx" // Return server error class if status code is invalid
	}
	return fmt.Sprintf("%dxx", code/100)
}
