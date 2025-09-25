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

func TestUpdatePluginsHandler_GatewaySuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	// Existing plugin in the gateway (with ID) to be updated
	existingPluginID := uuid.New().String()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{ID: existingPluginID, Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Priority: 1, Parallel: false, Settings: map[string]interface{}{"limit": 100}},
		},
		UpdatedAt: time.Now(),
	}

	// Incoming update attempts to change name (should be preserved as original), toggles enabled and priority
	payload := request.UpdatePluginsRequest{
		Type: "gateway",
		ID:   gatewayID.String(),
		Plugins: []map[string]any{
			{
				"id":       existingPluginID,
				"name":     "should_be_ignored",
				"enabled":  false,
				"stage":    string(types.PreRequest),
				"priority": 5,
				"parallel": true,
				"settings": map[string]any{"limit": 200},
			},
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	// Capture Update to ensure ID and Name are preserved
	gatewayRepo.On("Update", mock.Anything, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		if len(g.RequiredPlugins) != 1 {
			return false
		}
		p := g.RequiredPlugins[0]
		return p.ID == existingPluginID && p.Name == "rate_limiter" && p.Enabled == false && p.Priority == 5 && p.Parallel == true
	})).Return(nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestUpdatePluginsHandler_RuleSuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	ruleID := uuid.New()
	gatewayID := uuid.New()
	existingPluginID := uuid.New().String()
	existingRule := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		Path:      "/test",
		ServiceID: uuid.New(),
		Methods:   []string{"GET"},
		PluginChain: []types.PluginConfig{
			{ID: existingPluginID, Name: "cors", Enabled: true, Stage: types.PreRequest, Priority: 0, Parallel: false, Settings: map[string]interface{}{"allowed_origins": []string{"*"}}},
		},
		UpdatedAt: time.Now(),
	}

	payload := request.UpdatePluginsRequest{
		Type: "rule",
		ID:   ruleID.String(),
		Plugins: []map[string]any{
			{
				"id":       existingPluginID,
				"enabled":  false,
				"priority": 2,
				"parallel": true,
				"settings": map[string]any{"allowed_origins": []string{"example.com"}},
			},
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(existingRule, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	ruleRepo.On("Update", mock.Anything, mock.MatchedBy(func(r *forwarding_rule.ForwardingRule) bool {
		if len(r.PluginChain) != 1 {
			return false
		}
		p := r.PluginChain[0]
		return p.ID == existingPluginID && p.Name == "cors" && p.Enabled == false && p.Priority == 2 && p.Parallel == true
	})).Return(nil)
	// Expect cache refresh after update
	ruleRepo.On("ListRules", mock.Anything, gatewayID).Return([]forwarding_rule.ForwardingRule{}, nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestUpdatePluginsHandler_InvalidType(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	payload := map[string]any{
		"type":    "invalid",
		"id":      uuid.New().String(),
		"plugins": []map[string]any{{"id": uuid.New().String()}},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestUpdatePluginsHandler_InvalidUUID(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	gwReq := map[string]any{"type": "gateway", "id": "not-a-uuid", "plugins": []map[string]any{{"id": uuid.New().String()}}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	gwHTTPReq := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(gwBody))
	gwHTTPReq.Header.Set("Content-Type", "application/json")
	gwResp, err := app.Test(gwHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, gwResp.StatusCode)

	ruleReq := map[string]any{"type": "rule", "id": "not-a-uuid", "plugins": []map[string]any{{"id": uuid.New().String()}}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	ruleHTTPReq := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(ruleBody))
	ruleHTTPReq.Header.Set("Content-Type", "application/json")
	ruleResp, err := app.Test(ruleHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, ruleResp.StatusCode)
}

func TestUpdatePluginsHandler_NotFound(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	gwReq := request.UpdatePluginsRequest{Type: "gateway", ID: gatewayID.String(), Plugins: []map[string]any{{"id": uuid.New().String()}}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(nil, assert.AnError)
	gwHTTPReq := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(gwBody))
	gwHTTPReq.Header.Set("Content-Type", "application/json")
	gwResp, err := app.Test(gwHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, gwResp.StatusCode)

	ruleID := uuid.New()
	ruleReq := request.UpdatePluginsRequest{Type: "rule", ID: ruleID.String(), Plugins: []map[string]any{{"id": uuid.New().String()}}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, assert.AnError)
	ruleHTTPReq := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(ruleBody))
	ruleHTTPReq.Header.Set("Content-Type", "application/json")
	ruleResp, err := app.Test(ruleHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, ruleResp.StatusCode)
}

func TestUpdatePluginsHandler_PluginIDNotFound(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	// Existing gateway with one plugin
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "gw",
		RequiredPlugins: []types.PluginConfig{
			{ID: uuid.New().String(), Name: "cors", Enabled: true, Stage: types.PreRequest},
		},
	}
	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)

	// Incoming plugin ID does not exist in chain -> should return 404
	payload := request.UpdatePluginsRequest{Type: "gateway", ID: gatewayID.String(), Plugins: []map[string]any{{"id": uuid.New().String(), "enabled": false}}}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode)
}

func TestUpdatePluginsHandler_ValidatorError(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	existingPluginID := uuid.New().String()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{ID: existingPluginID, Name: "rate_limiter", Enabled: true, Stage: types.PreRequest},
		},
	}

	payload := request.UpdatePluginsRequest{Type: "gateway", ID: gatewayID.String(), Plugins: []map[string]any{{"id": existingPluginID, "enabled": false}}}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(assert.AnError)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestUpdatePluginsHandler_InvalidPayload_MissingPluginID(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewUpdatePluginsHandler(logger, gatewayRepo, ruleRepo, validator, publisher)

	app := fiber.New()
	app.Put("/api/v1/plugins", handler.Handle)

	payload := map[string]any{
		"type":    "gateway",
		"id":      uuid.New().String(),
		"plugins": []map[string]any{{"enabled": false}}, // missing id
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}
