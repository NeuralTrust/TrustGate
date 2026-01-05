package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugin/mocks"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockUpdateGatewayCache is a mock for UpdateGatewayCache
type mockUpdateGatewayCache struct {
	mock.Mock
}

func (m *mockUpdateGatewayCache) Update(ctx context.Context, gateway *domainGateway.Gateway) error {
	args := m.Called(ctx, gateway)
	return args.Error(0)
}

// mockTelemetryExportersValidator is a mock for ExportersValidator
type mockTelemetryExportersValidator struct {
	mock.Mock
}

func (m *mockTelemetryExportersValidator) Validate(exporters []types.ExporterDTO) error {
	args := m.Called(exporters)
	return args.Error(0)
}

func setupCreator(
	t *testing.T,
	repo *gatewayMocks.Repository,
	updateCache *mockUpdateGatewayCache,
	pluginValidator *pluginmocks.ValidatePluginChain,
	telemetryValidator *mockTelemetryExportersValidator,
) Creator {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
	return NewCreator(logger, repo, updateCache, pluginValidator, telemetryValidator)
}

func TestCreator_Create_Success(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	expectedID := uuid.New()

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil).Run(func(args mock.Arguments) {
		gateway := args.Get(1).(*domainGateway.Gateway)
		gateway.ID = expectedID
	})
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Test GatewayDTO", result.Name)
	assert.Equal(t, "active", result.Status)
	assert.NotEqual(t, uuid.Nil, result.ID)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_WithGatewayID(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	expectedID := uuid.New()
	gatewayIDStr := expectedID.String()

	pluginValidator.On("Validate", ctx, expectedID, req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		return g.ID == expectedID
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, gatewayIDStr)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, expectedID, result.ID)
	assert.Equal(t, "Test GatewayDTO", result.Name)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_WithSecurityConfig(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		SecurityConfig: &request.SecurityConfigRequest{
			AllowedHosts:            []string{"example.com"},
			AllowedHostsAreRegex:    false,
			SSLRedirect:             true,
			SSLHost:                 "example.com",
			SSLProxyHeaders:         map[string]string{"X-Forwarded-Proto": "https"},
			STSSeconds:              31536000,
			STSIncludeSubdomains:    true,
			FrameDeny:               true,
			CustomFrameOptionsValue: "DENY",
			ReferrerPolicy:          "no-referrer",
			ContentSecurityPolicy:   "default-src 'self'",
			ContentTypeNosniff:      true,
			BrowserXSSFilter:        true,
			IsDevelopment:           false,
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		return g.SecurityConfig != nil &&
			len(g.SecurityConfig.AllowedHosts) == 1 &&
			g.SecurityConfig.AllowedHosts[0] == "example.com" &&
			g.SecurityConfig.SSLRedirect == true
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.SecurityConfig)
	assert.Equal(t, []string{"example.com"}, result.SecurityConfig.AllowedHosts)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_WithTelemetry(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		Telemetry: &request.TelemetryRequest{
			Exporters: []request.ExporterRequest{
				{
					Name:     "kafka",
					Settings: map[string]interface{}{"broker": "localhost:9092"},
				},
			},
			ExtraParams:         map[string]string{"key": "value"},
			EnablePluginTraces:  true,
			EnableRequestTraces: true,
			HeaderMapping:       map[string]string{"conversation_id": "X-Conversation-ID"},
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	telemetryValidator.On("Validate", mock.MatchedBy(func(exporters []types.ExporterDTO) bool {
		return len(exporters) == 1 && exporters[0].Name == "kafka"
	})).Return(nil)
	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		return g.Telemetry != nil &&
			len(g.Telemetry.Exporters) == 1 &&
			g.Telemetry.Exporters[0].Name == "kafka" &&
			g.Telemetry.EnablePluginTraces == true
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.Telemetry)
	assert.Equal(t, 1, len(result.Telemetry.Exporters))
	assert.Equal(t, "kafka", result.Telemetry.Exporters[0].Name)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
	telemetryValidator.AssertExpectations(t)
}

func TestCreator_Create_WithSessionConfig(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		SessionConfig: &request.SessionConfigRequest{
			Enabled:       true,
			HeaderName:    "X-Session-ID",
			BodyParamName: "session_id",
			Mapping:       "user_id",
			TTL:           3600,
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		return g.SessionConfig != nil &&
			g.SessionConfig.Enabled == true &&
			g.SessionConfig.HeaderName == "X-Session-ID" &&
			g.SessionConfig.TTL == 3600
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.SessionConfig)
	assert.Equal(t, true, result.SessionConfig.Enabled)
	assert.Equal(t, "X-Session-ID", result.SessionConfig.HeaderName)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_WithClientTLSConfig(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		TlS: map[string]request.ClientTLSConfigRequest{
			"backend1": {
				AllowInsecureConnections: false,
				CACert:                   "ca-cert",
				ClientCerts: request.ClientTLSCertRequest{
					Certificate: "client-cert",
					PrivateKey:  "client-key",
				},
				CipherSuites:        []uint16{0x002F},
				CurvePreferences:    []uint16{0x0017},
				DisableSystemCAPool: false,
				MinVersion:          "TLS12",
				MaxVersion:          "TLS13",
			},
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		return len(g.ClientTLSConfig) > 0 &&
			g.ClientTLSConfig["backend1"].CACerts == "ca-cert"
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.ClientTLSConfig)
	assert.NotNil(t, result.ClientTLSConfig["backend1"])
	assert.Equal(t, "ca-cert", result.ClientTLSConfig["backend1"].CACerts)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_SetsCreatedAtAndUpdatedAt(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	beforeTime := time.Now()

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.MatchedBy(func(g *domainGateway.Gateway) bool {
		afterTime := time.Now()
		return !g.CreatedAt.IsZero() &&
			!g.UpdatedAt.IsZero() &&
			(g.CreatedAt.After(beforeTime) || g.CreatedAt.Equal(beforeTime)) &&
			(g.CreatedAt.Before(afterTime) || g.CreatedAt.Equal(afterTime)) &&
			g.CreatedAt.Equal(g.UpdatedAt)
	})).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)

	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.CreatedAt.IsZero())
	assert.False(t, result.UpdatedAt.IsZero())
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_InvalidGatewayID(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	result, err := creator.Create(ctx, req, "invalid-uuid")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse gateway id")
	repo.AssertNotCalled(t, "Save")
	updateCache.AssertNotCalled(t, "Update")
	pluginValidator.AssertNotCalled(t, "Validate")
}

func TestCreator_Create_PluginChainValidationFails(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	validationError := errors.New("plugin chain validation failed")

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(validationError)

	result, err := creator.Create(ctx, req, "")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to validate plugin chain")
	repo.AssertNotCalled(t, "Save")
	updateCache.AssertNotCalled(t, "Update")
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_DuplicateTelemetryExporters(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		Telemetry: &request.TelemetryRequest{
			Exporters: []request.ExporterRequest{
				{
					Name:     "kafka",
					Settings: map[string]interface{}{"broker": "localhost:9092"},
				},
				{
					Name:     "kafka", // Duplicate
					Settings: map[string]interface{}{"broker": "localhost:9093"},
				},
			},
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()

	result, err := creator.Create(ctx, req, "")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "duplicate telemetry exporter provider")
	repo.AssertNotCalled(t, "Save")
	updateCache.AssertNotCalled(t, "Update")
	pluginValidator.AssertNotCalled(t, "Validate")
	telemetryValidator.AssertNotCalled(t, "Validate")
}

func TestCreator_Create_TelemetryValidationFails(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:   "Test GatewayDTO",
		Status: "active",
		Telemetry: &request.TelemetryRequest{
			Exporters: []request.ExporterRequest{
				{
					Name:     "invalid",
					Settings: map[string]interface{}{},
				},
			},
		},
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	validationError := errors.New("invalid exporter")

	telemetryValidator.On("Validate", mock.AnythingOfType("[]types.ExporterDTO")).Return(validationError)

	result, err := creator.Create(ctx, req, "")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to validate telemetry providers")
	repo.AssertNotCalled(t, "Save")
	updateCache.AssertNotCalled(t, "Update")
	pluginValidator.AssertNotCalled(t, "Validate")
	telemetryValidator.AssertExpectations(t)
}

func TestCreator_Create_RepositorySaveFails(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	saveError := errors.New("database error")

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(saveError)

	result, err := creator.Create(ctx, req, "")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create gateway")
	repo.AssertExpectations(t)
	updateCache.AssertNotCalled(t, "Update")
	pluginValidator.AssertExpectations(t)
}

func TestCreator_Create_CacheUpdateFails_StillReturnsSuccess(t *testing.T) {
	repo := new(gatewayMocks.Repository)
	updateCache := new(mockUpdateGatewayCache)
	pluginValidator := pluginmocks.NewValidatePluginChain(t)
	telemetryValidator := new(mockTelemetryExportersValidator)

	creator := setupCreator(t, repo, updateCache, pluginValidator, telemetryValidator)

	req := &request.CreateGatewayRequest{
		Name:            "Test GatewayDTO",
		Status:          "active",
		RequiredPlugins: []pluginTypes.PluginConfig{},
	}

	ctx := context.Background()
	cacheError := errors.New("cache error")

	pluginValidator.On("Validate", ctx, mock.AnythingOfType("uuid.UUID"), req.RequiredPlugins).Return(nil)
	repo.On("Save", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(nil)
	updateCache.On("Update", ctx, mock.AnythingOfType("*gateway.Gateway")).Return(cacheError)

	// Cache update failure should not fail the creation
	result, err := creator.Create(ctx, req, "")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	repo.AssertExpectations(t)
	updateCache.AssertExpectations(t)
	pluginValidator.AssertExpectations(t)
}
