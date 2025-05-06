package middleware_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthMiddleware_NoAPIKey(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAuthMiddleware_InvalidAPIKey(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	// Mock an invalid API key (expired)
	expiredTime := time.Now().Add(-1 * time.Hour)
	mockAPIKey := &domain.APIKey{
		ID:        uuid.New(),
		Key:       "test-key",
		Name:      "Test Key",
		Active:    true,
		GatewayID: uuid.New(),
		ExpiresAt: expiredTime,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}

	mockKeyFinder.EXPECT().Find(mock.Anything, "test-key").Return(mockAPIKey, nil)

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-TG-API-Key", "test-key")
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAuthMiddleware_KeyFinderError(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	mockKeyFinder.EXPECT().Find(mock.Anything, "test-key").Return(nil, errors.New("database error"))

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-TG-API-Key", "test-key")
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}

func TestAuthMiddleware_GatewayFinderError(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	gatewayID := uuid.New()
	validTime := time.Now().Add(1 * time.Hour)
	mockAPIKey := &domain.APIKey{
		ID:        uuid.New(),
		Key:       "test-key",
		Name:      "Test Key",
		Active:    true,
		GatewayID: gatewayID,
		ExpiresAt: validTime,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}

	mockKeyFinder.EXPECT().Find(mock.Anything, "test-key").Return(mockAPIKey, nil)
	mockGatewayFinder.EXPECT().Find(mock.Anything, gatewayID).Return(nil, errors.New("gateway not found"))

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-TG-API-Key", "test-key")
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}

func TestAuthMiddleware_Success(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	gatewayID := uuid.New()
	validTime := time.Now().Add(1 * time.Hour)
	mockAPIKey := &domain.APIKey{
		ID:        uuid.New(),
		Key:       "test-key",
		Name:      "Test Key",
		Active:    true,
		GatewayID: gatewayID,
		ExpiresAt: validTime,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}

	mockGatewayData := &types.GatewayData{
		Gateway: &types.Gateway{
			ID:   gatewayID.String(),
			Name: "Test Gateway",
		},
		Rules: []types.ForwardingRule{},
	}

	mockKeyFinder.EXPECT().Find(mock.Anything, "test-key").Return(mockAPIKey, nil)
	mockGatewayFinder.EXPECT().Find(mock.Anything, gatewayID).Return(mockGatewayData, nil)

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	var contextAPIKey string
	var contextGatewayID string
	var contextAPIKeyID string
	var contextMetadata map[string]interface{}
	var contextGatewayData *types.GatewayData

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		if apiKey, ok := c.Locals(common.ApiKeyContextKey).(string); ok {
			contextAPIKey = apiKey
		}
		if gatewayID, ok := c.Locals(common.GatewayContextKey).(string); ok {
			contextGatewayID = gatewayID
		}
		if apiKeyID, ok := c.Locals(common.ApiKeyIdContextKey).(string); ok {
			contextAPIKeyID = apiKeyID
		}
		if metadata, ok := c.Locals(common.MetadataKey).(map[string]interface{}); ok {
			contextMetadata = metadata
		}
		if gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData); ok {
			contextGatewayData = gatewayData
		}
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-TG-API-Key", "test-key")
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "test-key", contextAPIKey)
	assert.Equal(t, gatewayID.String(), contextGatewayID)
	assert.Equal(t, mockAPIKey.ID.String(), contextAPIKeyID)
	assert.Equal(t, "test-key", contextMetadata[string(common.ApiKeyContextKey)])
	assert.Equal(t, gatewayID.String(), contextMetadata[string(common.GatewayContextKey)])
	assert.Equal(t, mockGatewayData, contextGatewayData)
}

func TestAuthMiddleware_InactiveAPIKey(t *testing.T) {
	// Setup
	logger := logrus.New()
	mockKeyFinder := mocks.NewFinder(t)
	mockGatewayFinder := mocks.NewDataFinder(t)

	// Mock an inactive API key
	validTime := time.Now().Add(1 * time.Hour)
	mockAPIKey := &domain.APIKey{
		ID:        uuid.New(),
		Key:       "test-key",
		Name:      "Test Key",
		Active:    false, // Inactive key
		GatewayID: uuid.New(),
		ExpiresAt: validTime,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}

	mockKeyFinder.EXPECT().Find(mock.Anything, "test-key").Return(mockAPIKey, nil)

	authMiddleware := middleware.NewAuthMiddleware(logger, mockKeyFinder, mockGatewayFinder)

	app := fiber.New()
	app.Use(authMiddleware.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-TG-API-Key", "test-key")
	resp, err := app.Test(req)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
