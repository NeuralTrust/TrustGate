package http

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	chainValidatorMocks "github.com/NeuralTrust/TrustGate/pkg/app/plugin/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	ruleMocks "github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule/mocks"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	publisherMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUpdatePluginsHandler_Operations(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	t.Run("Add plugin to gateway", func(t *testing.T) {
		gatewayID := uuid.New()
		existingGateway := &domainGateway.Gateway{
			ID:   gatewayID,
			Name: "test-gateway",
			RequiredPlugins: []types.PluginConfig{
				{
					Name:    "rate_limiter",
					Enabled: true,
					Stage:   types.PreRequest,
					Settings: map[string]interface{}{
						"limit": 100,
					},
				},
			},
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "gateway",
			ID:   gatewayID.String(),
			Updates: []request.PluginUpdate{
				{
					Operation: request.PluginOperationAdd,
					Plugin: types.PluginConfig{
						Name:    "cors",
						Enabled: true,
						Stage:   types.PreRequest,
						Settings: map[string]interface{}{
							"allowed_origins": []string{"*"},
						},
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("Edit plugin in gateway", func(t *testing.T) {
		gatewayID := uuid.New()
		existingGateway := &domainGateway.Gateway{
			ID:   gatewayID,
			Name: "test-gateway",
			RequiredPlugins: []types.PluginConfig{
				{
					Name:    "rate_limiter",
					Enabled: true,
					Stage:   types.PreRequest,
					Settings: map[string]interface{}{
						"limit": 100,
					},
				},
			},
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "gateway",
			ID:   gatewayID.String(),
			Updates: []request.PluginUpdate{
				{
					Operation: request.PluginOperationEdit,
					Plugin: types.PluginConfig{
						Name:    "rate_limiter",
						Enabled: true,
						Stage:   types.PreRequest,
						Settings: map[string]interface{}{
							"limit": 200, // Changed limit
						},
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("Delete plugin from gateway", func(t *testing.T) {
		gatewayID := uuid.New()
		existingGateway := &domainGateway.Gateway{
			ID:   gatewayID,
			Name: "test-gateway",
			RequiredPlugins: []types.PluginConfig{
				{
					Name:    "rate_limiter",
					Enabled: true,
					Stage:   types.PreRequest,
				},
				{
					Name:    "cors",
					Enabled: true,
					Stage:   types.PreRequest,
				},
			},
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "gateway",
			ID:   gatewayID.String(),
			Updates: []request.PluginUpdate{
				{
					Operation:  request.PluginOperationDelete,
					PluginName: "cors",
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("Multiple operations in single request", func(t *testing.T) {
		gatewayID := uuid.New()
		existingGateway := &domainGateway.Gateway{
			ID:   gatewayID,
			Name: "test-gateway",
			RequiredPlugins: []types.PluginConfig{
				{
					Name:    "rate_limiter",
					Enabled: true,
					Stage:   types.PreRequest,
					Settings: map[string]interface{}{
						"limit": 100,
					},
				},
				{
					Name:    "old_plugin",
					Enabled: true,
					Stage:   types.PreRequest,
				},
			},
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "gateway",
			ID:   gatewayID.String(),
			Updates: []request.PluginUpdate{
				{
					Operation:  request.PluginOperationDelete,
					PluginName: "old_plugin",
				},
				{
					Operation: request.PluginOperationAdd,
					Plugin: types.PluginConfig{
						Name:    "cors",
						Enabled: true,
						Stage:   types.PreRequest,
						Settings: map[string]interface{}{
							"allowed_origins": []string{"*"},
						},
					},
				},
				{
					Operation: request.PluginOperationEdit,
					Plugin: types.PluginConfig{
						Name:    "rate_limiter",
						Enabled: true,
						Stage:   types.PreRequest,
						Settings: map[string]interface{}{
							"limit": 500,
						},
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("Validation error - no updates provided", func(t *testing.T) {
		gatewayID := uuid.New()

		reqBody := request.UpdatePluginsRequest{
			Type:    "gateway",
			ID:      gatewayID.String(),
			Updates: []request.PluginUpdate{}, // Empty updates
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)
	})

	t.Run("Edit plugin in rule", func(t *testing.T) {
		ruleID := uuid.New()
		gatewayID := uuid.New()
		existingRule := &forwarding_rule.ForwardingRule{
			ID:        ruleID,
			GatewayID: gatewayID,
			Name:      "test-rule",
			PluginChain: []types.PluginConfig{
				{
					Name:    "data_masking",
					Enabled: true,
					Stage:   types.PostResponse,
					Settings: map[string]interface{}{
						"patterns": []string{"ssn"},
					},
				},
			},
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "rule",
			ID:   ruleID.String(),
			Updates: []request.PluginUpdate{
				{
					Operation: request.PluginOperationEdit,
					Plugin: types.PluginConfig{
						Name:    "data_masking",
						Enabled: false, // Disable the plugin
						Stage:   types.PostResponse,
						Settings: map[string]interface{}{
							"patterns": []string{"ssn", "credit_card"},
						},
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(existingRule, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		ruleRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, -1)
		require.NoError(t, err)
		assert.Equal(t, 204, resp.StatusCode)
	})
}
