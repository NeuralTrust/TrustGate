package plugin_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidate_Success(t *testing.T) {

	pluginMock := new(mocks.Plugin)
	pluginMock.On("RequiredPlugins").Return([]string{"neuraltrust_guardrail"})
	pluginMock.On("Name").Return("context_security")
	pluginMock.On("Stages").Return([]types.Stage{types.PreRequest})

	pluginManagerMock := new(mocks.Manager)
	pluginManagerMock.On("ValidatePlugin", mock.Anything, mock.Anything).Return(nil)
	pluginManagerMock.On("GetPlugin", mock.Anything).Return(pluginMock)

	gatewayRepositoryMock := new(mocks.Repository)

	pluginsConfig := []types.PluginConfig{
		{
			Name:     "context_security",
			Enabled:  true,
			Level:    types.Level("gateway"),
			Stage:    types.PreRequest,
			Priority: 1,
			Parallel: false,
			Settings: map[string]interface{}{},
		},
		{
			Name:     "neuraltrust_guardrail",
			Enabled:  true,
			Level:    types.Level("gateway"),
			Stage:    types.PreRequest,
			Priority: 1,
			Parallel: false,
			Settings: map[string]interface{}{},
		},
	}
	validator := plugin.NewValidatePluginChain(pluginManagerMock, gatewayRepositoryMock)
	err := validator.Validate(context.Background(), uuid.New(), pluginsConfig)
	assert.NoError(t, err)
}

func TestValidate_MissingRequiredPlugin(t *testing.T) {

	pluginMock := new(mocks.Plugin)
	pluginMock.On("RequiredPlugins").Return([]string{"neuraltrust_guardrail"}).Once()
	pluginMock.On("Name").Return("context_security").Once()
	pluginMock.On("Stages").Return([]types.Stage{types.PreRequest}).Once()

	pluginManagerMock := new(mocks.Manager)
	pluginManagerMock.On("ValidatePlugin", mock.Anything, mock.Anything).Return(nil).Once()
	pluginManagerMock.On("GetPlugin", mock.Anything).Return(pluginMock).Once()
	pluginManagerMock.On("GetChains", mock.Anything, mock.Anything).Return([][]types.PluginConfig{}).Once()

	gatewayRepositoryMock := new(mocks.Repository)
	gatewayRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(
		&gateway.Gateway{
			ID:              uuid.New(),
			RequiredPlugins: []types.PluginConfig{},
		},
		nil,
	)
	pluginsConfig := []types.PluginConfig{
		{
			Name:     "context_security",
			Enabled:  true,
			Level:    types.Level("gateway"),
			Stage:    types.PreRequest,
			Priority: 1,
			Parallel: false,
			Settings: map[string]interface{}{},
		},
	}
	validator := plugin.NewValidatePluginChain(pluginManagerMock, gatewayRepositoryMock)
	err := validator.Validate(context.Background(), uuid.New(), pluginsConfig)
	assert.ErrorIs(t, err, types.ErrRequiredPluginNotFound)
	assert.Error(t, err)
}

func TestValidate_SuccessPluginInGateway(t *testing.T) {

	pluginMock := new(mocks.Plugin)
	pluginMock.On("RequiredPlugins").Return([]string{"neuraltrust_guardrail"}).Once()
	pluginMock.On("Name").Return("context_security").Once()
	pluginMock.On("Stages").Return([]types.Stage{types.PreRequest}).Once()

	pluginManagerMock := new(mocks.Manager)
	pluginManagerMock.On("ValidatePlugin", mock.Anything, mock.Anything).Return(nil).Once()
	pluginManagerMock.On("GetPlugin", mock.Anything).Return(pluginMock).Once()

	gatewayRepositoryMock := new(mocks.Repository)
	gatewayRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(
		&gateway.Gateway{
			ID: uuid.New(),
			RequiredPlugins: []types.PluginConfig{
				{
					Name:     "neuraltrust_guardrail",
					Enabled:  true,
					Level:    "gateway",
					Stage:    types.PreRequest,
					Priority: 1,
					Parallel: false,
					Settings: map[string]interface{}{},
				},
			},
		},
		nil,
	)

	pluginsConfig := []types.PluginConfig{
		{
			Name:     "context_security",
			Enabled:  true,
			Level:    types.Level("gateway"),
			Stage:    types.PreRequest,
			Priority: 1,
			Parallel: false,
			Settings: map[string]interface{}{},
		},
	}
	validator := plugin.NewValidatePluginChain(pluginManagerMock, gatewayRepositoryMock)
	err := validator.Validate(context.Background(), uuid.New(), pluginsConfig)
	assert.NoError(t, err)
}

func TestValidate_FailedPluginInChain_NotSameStage(t *testing.T) {

	pluginMock := new(mocks.Plugin)
	pluginMock.On("RequiredPlugins").Return([]string{"neuraltrust_guardrail"}).Once()
	pluginMock.On("Name").Return("context_security").Once()
	pluginMock.On("Stages").Return([]types.Stage{types.PreRequest}).Once()

	pluginManagerMock := new(mocks.Manager)
	pluginManagerMock.On("ValidatePlugin", mock.Anything, mock.Anything).Return(nil).Once()
	pluginManagerMock.On("GetPlugin", mock.Anything).Return(pluginMock).Once()

	gatewayRepositoryMock := new(mocks.Repository)
	gatewayRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(
		&gateway.Gateway{
			ID: uuid.New(),
			RequiredPlugins: []types.PluginConfig{
				{
					Name:     "neuraltrust_guardrail",
					Enabled:  true,
					Level:    "gateway",
					Stage:    types.PostResponse,
					Priority: 1,
					Parallel: false,
					Settings: map[string]interface{}{},
				},
			},
		},
		nil,
	)

	pluginsConfig := []types.PluginConfig{
		{
			Name:     "context_security",
			Enabled:  true,
			Level:    types.Level("gateway"),
			Stage:    types.PreRequest,
			Priority: 1,
			Parallel: false,
			Settings: map[string]interface{}{},
		},
	}
	validator := plugin.NewValidatePluginChain(pluginManagerMock, gatewayRepositoryMock)
	err := validator.Validate(context.Background(), uuid.New(), pluginsConfig)
	assert.ErrorIs(t, err, types.ErrRequiredPluginNotFound)
	assert.Error(t, err)
}
