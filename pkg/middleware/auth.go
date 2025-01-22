package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthMiddleware struct {
	logger *logrus.Logger
	db     *database.Repository
}

func NewAuthMiddleware(logger *logrus.Logger, repo *database.Repository) *AuthMiddleware {
	return &AuthMiddleware{
		logger: logger,
		db:     repo,
	}
}

func (m *AuthMiddleware) ValidateAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for system endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/__/") {
			c.Next()
			return
		}

		// Extract API key from X-Api-Key header first, then fallback to Authorization header
		apiKey := c.GetHeader("X-Api-Key")
		if apiKey == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			m.logger.Debug("No API key provided")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			return
		}

		// Get gateway ID from context
		gatewayID, err := getContextValue[string](c.Request.Context(), common.GatewayContextKey)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid gateway ID"})
			return
		}

		// Validate API key
		valid, err := m.db.ValidateAPIKey(c.Request.Context(), gatewayID, apiKey)
		if err != nil {
			m.logger.WithError(err).Error("Database error during API key validation")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		if !valid {
			m.logger.Debug("Invalid API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			return
		}

		// Initialize metadata map
		metadata := map[string]interface{}{
			"api_key":    apiKey,
			"gateway_id": gatewayID,
		}

		// Store in context
		c.Set("api_key", apiKey)
		c.Set("metadata", metadata)

		// Set in request context for plugins
		ctx := context.WithValue(c.Request.Context(), common.MetadataKey, metadata)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// Add helper function for safe type assertions
func getContextValue[T any](ctx context.Context, key interface{}) (T, error) {
	value := ctx.Value(key)
	if value == nil {
		var zero T
		return zero, fmt.Errorf("value not found in context for key: %v", key)
	}
	result, ok := value.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return result, nil
}
