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
	publisherMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDeletePluginsHandler_GatewaySuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	plugin1ID := uuid.NewString()
	plugin2ID := uuid.NewString()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{ID: plugin1ID, Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
			{ID: plugin2ID, Name: "cors", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"allowed_origins": []string{"*"}}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := map[string]interface{}{
		"type":       "gateway",
		"id":         gatewayID.String(),
		"plugin_ids": []string{plugin2ID},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestDeletePluginsHandler_RuleSuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	ruleID := uuid.New()
	gatewayID := uuid.New()
	plugin1ID := uuid.NewString()
	plugin2ID := uuid.NewString()
	existingRule := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		Path:      "/test",
		ServiceID: uuid.New(),
		Methods:   []string{"GET"},
		PluginChain: []types.PluginConfig{
			{ID: plugin1ID, Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
			{ID: plugin2ID, Name: "cors", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"allowed_origins": []string{"*"}}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := map[string]interface{}{
		"type":       "rule",
		"id":         ruleID.String(),
		"plugin_ids": []string{plugin2ID},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(existingRule, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	ruleRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestDeletePluginsHandler_InvalidType(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	reqBody := map[string]interface{}{
		"type":       "invalid",
		"id":         uuid.New().String(),
		"plugin_ids": []string{uuid.NewString()},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestDeletePluginsHandler_InvalidUUID(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	// GatewayDTO invalid UUID
	gwReq := map[string]interface{}{"type": "gateway", "id": "not-a-uuid", "plugin_ids": []string{uuid.NewString()}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	req := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(gwBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)

	// Rule invalid UUID
	ruleReq := map[string]interface{}{"type": "rule", "id": "not-a-uuid", "plugin_ids": []string{uuid.NewString()}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	req2 := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(ruleBody))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := app.Test(req2, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp2.StatusCode)
}

func TestDeletePluginsHandler_NotFound(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	gwReq := map[string]interface{}{"type": "gateway", "id": gatewayID.String(), "plugin_ids": []string{uuid.NewString()}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(nil, assert.AnError)
	gwHTTPReq := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(gwBody))
	gwHTTPReq.Header.Set("Content-Type", "application/json")
	gwResp, err := app.Test(gwHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, gwResp.StatusCode)

	ruleID := uuid.New()
	ruleReq := map[string]interface{}{"type": "rule", "id": ruleID.String(), "plugin_ids": []string{uuid.NewString()}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, assert.AnError)
	ruleHTTPReq := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(ruleBody))
	ruleHTTPReq.Header.Set("Content-Type", "application/json")
	ruleResp, err := app.Test(ruleHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, ruleResp.StatusCode)
}

func TestDeletePluginsHandler_ValidatorError(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewDeletePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Delete("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	plugin1ID := uuid.NewString()
	plugin2ID := uuid.NewString()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{ID: plugin1ID, Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
			{ID: plugin2ID, Name: "cors", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"allowed_origins": []string{"*"}}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := map[string]interface{}{
		"type":       "gateway",
		"id":         gatewayID.String(),
		"plugin_ids": []string{plugin2ID},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(assert.AnError)

	req := httptest.NewRequest("DELETE", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}
