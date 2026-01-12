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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAddPluginsHandler_GatewaySuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := request.AddPluginsRequest{
		Type: "gateway",
		ID:   gatewayID.String(),
		Plugins: []types.PluginConfig{
			{
				Name:     "cors",
				Enabled:  true,
				Stage:    types.PreRequest,
				Priority: 1,
				Parallel: false,
				Settings: map[string]interface{}{"allowed_origins": []string{"*"}},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestAddPluginsHandler_RuleSuccess(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	ruleID := uuid.New()
	gatewayID := uuid.New()
	existingRule := &forwarding_rule.ForwardingRule{
		ID:        ruleID,
		GatewayID: gatewayID,
		Path:      "/test",
		ServiceID: uuid.New(),
		Methods:   []string{"GET"},
		PluginChain: []types.PluginConfig{
			{Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := request.AddPluginsRequest{
		Type: "rule",
		ID:   ruleID.String(),
		Plugins: []types.PluginConfig{
			{
				Name:     "cors",
				Enabled:  true,
				Stage:    types.PreRequest,
				Priority: 1,
				Parallel: false,
				Settings: map[string]interface{}{"allowed_origins": []string{"*"}},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(existingRule, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
	ruleRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
	publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 204, resp.StatusCode)
}

func TestAddPluginsHandler_DuplicatePluginSameStage(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
		},
		UpdatedAt: time.Now(),
	}

	// Attempt to add the same plugin name and same stage -> should fail 400
	reqBody := request.AddPluginsRequest{
		Type: "gateway",
		ID:   gatewayID.String(),
		Plugins: []types.PluginConfig{
			{Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 200}},
		},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)

	req := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestAddPluginsHandler_InvalidType(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	reqBody := map[string]interface{}{
		"type":    "invalid",
		"id":      uuid.New().String(),
		"plugins": []map[string]interface{}{{"name": "cors", "stage": string(types.PreRequest)}},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}

func TestAddPluginsHandler_InvalidUUID(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	// GatewayDTO invalid UUID
	gwReq := map[string]interface{}{"type": "gateway", "id": "not-a-uuid", "plugins": []map[string]interface{}{{"name": "cors", "stage": string(types.PreRequest)}}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	gwHTTPReq := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(gwBody))
	gwHTTPReq.Header.Set("Content-Type", "application/json")
	gwResp, err := app.Test(gwHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, gwResp.StatusCode)

	// Rule invalid UUID
	ruleReq := map[string]interface{}{"type": "rule", "id": "not-a-uuid", "plugins": []map[string]interface{}{{"name": "cors", "stage": string(types.PreRequest)}}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	ruleHTTPReq := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(ruleBody))
	ruleHTTPReq.Header.Set("Content-Type", "application/json")
	ruleResp, err := app.Test(ruleHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, ruleResp.StatusCode)
}

func TestAddPluginsHandler_NotFound(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	gwReq := request.AddPluginsRequest{Type: "gateway", ID: gatewayID.String(), Plugins: []types.PluginConfig{{Name: "cors", Stage: types.PreRequest}}}
	gwBody, err := json.Marshal(gwReq)
	require.NoError(t, err)
	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(nil, assert.AnError)
	gwHTTPReq := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(gwBody))
	gwHTTPReq.Header.Set("Content-Type", "application/json")
	gwResp, err := app.Test(gwHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, gwResp.StatusCode)

	ruleID := uuid.New()
	ruleReq := request.AddPluginsRequest{Type: "rule", ID: ruleID.String(), Plugins: []types.PluginConfig{{Name: "cors", Stage: types.PreRequest}}}
	ruleBody, err := json.Marshal(ruleReq)
	require.NoError(t, err)
	ruleRepo.On("GetRuleByID", mock.Anything, ruleID).Return(nil, assert.AnError)
	ruleHTTPReq := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(ruleBody))
	ruleHTTPReq.Header.Set("Content-Type", "application/json")
	ruleResp, err := app.Test(ruleHTTPReq, -1)
	require.NoError(t, err)
	assert.Equal(t, 404, ruleResp.StatusCode)
}

func TestAddPluginsHandler_ValidatorError(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(gatewayMocks.Repository)
	ruleRepo := new(ruleMocks.Repository)
	validator := new(chainValidatorMocks.ValidatePluginChain)
	publisher := new(publisherMocks.EventPublisher)

	handler := NewAddPluginsHandler(AddPluginsHandlerDeps{
		Logger:               logger,
		GatewayRepo:          gatewayRepo,
		RuleRepo:             ruleRepo,
		PluginChainValidator: validator,
		Publisher:            publisher,
		AuditService:         nil,
	})

	app := fiber.New()
	app.Post("/api/v1/plugins", handler.Handle)

	gatewayID := uuid.New()
	existingGateway := &domainGateway.Gateway{
		ID:   gatewayID,
		Name: "test-gateway",
		RequiredPlugins: []types.PluginConfig{
			{Name: "rate_limiter", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"limit": 100}},
		},
		UpdatedAt: time.Now(),
	}

	reqBody := request.AddPluginsRequest{
		Type: "gateway",
		ID:   gatewayID.String(),
		Plugins: []types.PluginConfig{
			{Name: "cors", Enabled: true, Stage: types.PreRequest, Settings: map[string]interface{}{"allowed_origins": []string{"*"}}},
		},
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
	validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(assert.AnError)

	req := httptest.NewRequest("POST", "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
}
