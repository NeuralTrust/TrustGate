package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock implementations
type mockGatewayRepo struct {
	mock.Mock
}

func (m *mockGatewayRepo) Save(ctx context.Context, gateway *domainGateway.Gateway) error {
	args := m.Called(ctx, gateway)
	return args.Error(0)
}

func (m *mockGatewayRepo) Get(ctx context.Context, id uuid.UUID) (*domainGateway.Gateway, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domainGateway.Gateway), args.Error(1)
}

func (m *mockGatewayRepo) List(ctx context.Context, offset, limit int) ([]domainGateway.Gateway, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]domainGateway.Gateway), args.Error(1)
}

func (m *mockGatewayRepo) Update(ctx context.Context, gateway *domainGateway.Gateway) error {
	args := m.Called(ctx, gateway)
	return args.Error(0)
}

func (m *mockGatewayRepo) Delete(id uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

type mockRuleRepo struct {
	mock.Mock
}

func (m *mockRuleRepo) GetRule(ctx context.Context, id uuid.UUID, gatewayID uuid.UUID) (*forwarding_rule.ForwardingRule, error) {
	args := m.Called(ctx, id, gatewayID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*forwarding_rule.ForwardingRule), args.Error(1)
}

func (m *mockRuleRepo) GetRuleByID(ctx context.Context, id uuid.UUID) (*forwarding_rule.ForwardingRule, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*forwarding_rule.ForwardingRule), args.Error(1)
}

func (m *mockRuleRepo) Create(ctx context.Context, rule *forwarding_rule.ForwardingRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockRuleRepo) ListRules(ctx context.Context, gatewayID uuid.UUID) ([]forwarding_rule.ForwardingRule, error) {
	args := m.Called(ctx, gatewayID)
	return args.Get(0).([]forwarding_rule.ForwardingRule), args.Error(1)
}

func (m *mockRuleRepo) Update(ctx context.Context, rule *forwarding_rule.ForwardingRule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *mockRuleRepo) Delete(ctx context.Context, id, gatewayID uuid.UUID) error {
	args := m.Called(ctx, id, gatewayID)
	return args.Error(0)
}

func (m *mockRuleRepo) UpdateRulesCache(ctx context.Context, gatewayID uuid.UUID, rules []forwarding_rule.ForwardingRule) error {
	args := m.Called(ctx, gatewayID, rules)
	return args.Error(0)
}

type mockPluginChainValidator struct {
	mock.Mock
}

func (m *mockPluginChainValidator) Validate(ctx context.Context, gatewayID uuid.UUID, plugins []types.PluginConfig) error {
	args := m.Called(ctx, gatewayID, plugins)
	return args.Error(0)
}

type mockEventPublisher struct {
	mock.Mock
}

func (m *mockEventPublisher) Publish(ctx context.Context, ch channel.Channel, ev event.Event) error {
	args := m.Called(ctx, ch, ev)
	return args.Error(0)
}

func TestUpdatePluginsHandler_GranularOperations(t *testing.T) {
	logger := logrus.New()
	gatewayRepo := new(mockGatewayRepo)
	ruleRepo := new(mockRuleRepo)
	validator := new(mockPluginChainValidator)
	publisher := new(mockEventPublisher)

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

		body, _ := json.Marshal(reqBody)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req, -1)
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

		body, _ := json.Marshal(reqBody)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req, -1)
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

		body, _ := json.Marshal(reqBody)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req, -1)
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

		body, _ := json.Marshal(reqBody)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req, -1)
		assert.Equal(t, 204, resp.StatusCode)
	})

	t.Run("Backward compatibility - full replacement", func(t *testing.T) {
		gatewayID := uuid.New()
		existingGateway := &domainGateway.Gateway{
			ID:        gatewayID,
			Name:      "test-gateway",
			UpdatedAt: time.Now(),
		}

		reqBody := request.UpdatePluginsRequest{
			Type: "gateway",
			ID:   gatewayID.String(),
			PluginChain: []types.PluginConfig{
				{
					Name:    "new_plugin_chain",
					Enabled: true,
					Stage:   types.PreRequest,
				},
			},
		}

		body, _ := json.Marshal(reqBody)

		gatewayRepo.On("Get", mock.Anything, gatewayID).Return(existingGateway, nil)
		validator.On("Validate", mock.Anything, gatewayID, mock.Anything).Return(nil)
		gatewayRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
		publisher.On("Publish", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		req := httptest.NewRequest("PUT", "/api/v1/plugins", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, _ := app.Test(req, -1)
		assert.Equal(t, 204, resp.StatusCode)
	})
}
