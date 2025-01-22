package middleware

import (
	"fmt"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
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

func (m *MetricsMiddleware) MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get gateway ID using GetString to avoid type assertions
		gatewayID := c.GetString(GatewayIDKey)
		if gatewayID == "" {
			m.logger.Error("Gateway ID not found in context")
			c.Next()
			return
		}

		// Record connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
		}

		// Process request
		c.Next()

		// Always record request total
		status := GetStatusClass(fmt.Sprint(c.Writer.Status()))
		metrics.GatewayRequestTotal.WithLabelValues(
			gatewayID,
			c.Request.Method,
			status,
		).Inc()

		// Decrease connections if enabled
		if metrics.Config.EnableConnections {
			metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
		}
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
