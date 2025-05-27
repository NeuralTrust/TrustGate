package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/NeuralTrust/TrustGate/pkg/domain/session/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSessionMiddleware_SavesSessionFromHeader(t *testing.T) {
	app := fiber.New()
	mockRepo := new(mocks.Repository)
	logger := logrus.New()
	mw := middleware.NewSessionMiddleware(logger, mockRepo)

	gatewayID := uuid.New()
	sessionID := "test-session-id"
	sessionConfig := &types.SessionConfig{
		Enabled:       true,
		HeaderName:    "X-Session-ID",
		TTL:           60,
		BodyParamName: "session_id",
	}

	gatewayData := &types.GatewayData{
		Gateway: &types.Gateway{
			SessionConfig: sessionConfig,
		},
	}

	// Expect the session to be saved
	mockRepo.On("Save", mock.Anything, mock.MatchedBy(func(sess *session.Session) bool {
		return sess.ID == sessionID && sess.GatewayID == gatewayID
	})).Return(nil).Once()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals(string(common.GatewayDataContextKey), gatewayData)
		c.Locals(common.GatewayContextKey, gatewayID.String())
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer([]byte(`{}`)))
	req.Header.Set("X-Session-ID", sessionID)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mockRepo.AssertExpectations(t)
}

func TestSessionMiddleware_SavesSessionFromBody(t *testing.T) {
	app := fiber.New()
	mockRepo := new(mocks.Repository)
	logger := logrus.New()
	mw := middleware.NewSessionMiddleware(logger, mockRepo)

	gatewayID := uuid.New()
	sessionID := "body-session-id"
	sessionConfig := &types.SessionConfig{
		Enabled:       true,
		HeaderName:    "X-Session-ID",
		BodyParamName: "session_id",
		TTL:           30,
	}

	gatewayData := &types.GatewayData{
		Gateway: &types.Gateway{
			SessionConfig: sessionConfig,
		},
	}

	mockRepo.On("Save", mock.Anything, mock.MatchedBy(func(sess *session.Session) bool {
		return sess.ID == sessionID && sess.GatewayID == gatewayID
	})).Return(nil).Once()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals(string(common.GatewayDataContextKey), gatewayData)
		c.Locals(common.GatewayContextKey, gatewayID.String())
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer([]byte(`{"session_id": "body-session-id"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	mockRepo.AssertExpectations(t)
}

func TestSessionMiddleware_SkipsIfNoSessionConfig(t *testing.T) {
	app := fiber.New()
	mockRepo := new(mocks.Repository)
	logger := logrus.New()
	mw := middleware.NewSessionMiddleware(logger, mockRepo)

	gatewayData := &types.GatewayData{
		Gateway: &types.Gateway{
			SessionConfig: nil,
		},
	}

	app.Use(func(c *fiber.Ctx) error {
		c.Locals(string(common.GatewayDataContextKey), gatewayData)
		c.Locals(common.GatewayContextKey, uuid.New().String())
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("Skipped")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	mockRepo.AssertNotCalled(t, "Save")
}
