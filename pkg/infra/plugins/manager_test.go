package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginMocks "github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface/mocks"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return logger
}

// newManagerForTesting creates a new manager instance for testing purposes.
// This bypasses the singleton pattern and does NOT call InitializePlugins.
func newManagerForTesting(logger *logrus.Logger) *manager {
	return &manager{
		plugins:        make(map[string]pluginiface.Plugin),
		configurations: make(map[string][][]pluginTypes.PluginConfig),
		logger:         logger,
	}
}

func newTestCollector() *metrics.Collector {
	return metrics.NewCollector("test-trace-id", &metrics.Config{
		EnablePluginTraces:  false,
		EnableRequestTraces: false,
	})
}

func TestManager_RegisterPlugin(t *testing.T) {
	t.Run("successfully registers a plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		err := m.RegisterPlugin(plugin)

		assert.NoError(t, err)
		assert.NotNil(t, m.plugins["test-plugin"])
	})

	t.Run("fails to register duplicate plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		plugin1 := pluginMocks.NewPlugin(t)
		plugin1.EXPECT().Name().Return("test-plugin")

		plugin2 := pluginMocks.NewPlugin(t)
		plugin2.EXPECT().Name().Return("test-plugin")

		err := m.RegisterPlugin(plugin1)
		assert.NoError(t, err)

		err = m.RegisterPlugin(plugin2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})
}

func TestManager_GetPlugin(t *testing.T) {
	t.Run("returns registered plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		_ = m.RegisterPlugin(plugin)

		result := m.GetPlugin("test-plugin")
		assert.Equal(t, plugin, result)
	})

	t.Run("returns nil for unregistered plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		result := m.GetPlugin("non-existent")
		assert.Nil(t, result)
	})
}

func TestManager_ValidatePlugin(t *testing.T) {
	t.Run("validates plugin successfully", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		config := pluginTypes.PluginConfig{Name: "test-plugin", Enabled: true}
		plugin.EXPECT().ValidateConfig(config).Return(nil)

		_ = m.RegisterPlugin(plugin)

		err := m.ValidatePlugin("test-plugin", config)
		assert.NoError(t, err)
	})

	t.Run("returns error for unknown plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		config := pluginTypes.PluginConfig{Name: "unknown", Enabled: true}
		err := m.ValidatePlugin("unknown", config)

		assert.Error(t, err)
		assert.ErrorIs(t, err, pluginTypes.ErrUnknownPlugin)
	})

	t.Run("returns validation error from plugin", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		config := pluginTypes.PluginConfig{Name: "test-plugin", Enabled: true}
		validationErr := errors.New("invalid config")
		plugin.EXPECT().ValidateConfig(config).Return(validationErr)

		_ = m.RegisterPlugin(plugin)

		err := m.ValidatePlugin("test-plugin", config)
		assert.Error(t, err)
		assert.Equal(t, validationErr, err)
	})
}

func TestManager_SetPluginChain(t *testing.T) {
	t.Run("sets plugin chain successfully", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true},
		}

		err := m.SetPluginChain("gateway-1", chains)
		assert.NoError(t, err)
		assert.Len(t, m.configurations["gateway-1"], 1)
	})

	t.Run("fails for unregistered plugin in chain", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		chains := []pluginTypes.PluginConfig{
			{Name: "unregistered-plugin", Enabled: true},
		}

		err := m.SetPluginChain("gateway-1", chains)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not registered")
	})

	t.Run("appends multiple chains for same gateway", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true},
		}

		_ = m.SetPluginChain("gateway-1", chains)
		_ = m.SetPluginChain("gateway-1", chains)

		assert.Len(t, m.configurations["gateway-1"], 2)
	})
}

func TestManager_ClearPluginChain(t *testing.T) {
	t.Run("clears existing chain", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true},
		}
		_ = m.SetPluginChain("gateway-1", chains)

		m.ClearPluginChain("gateway-1")

		assert.Nil(t, m.configurations["gateway-1"])
	})

	t.Run("does nothing for non-existent chain", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		// Should not panic
		m.ClearPluginChain("non-existent")
	})
}

func TestManager_GetChains(t *testing.T) {
	t.Run("returns chains for stage with fixed stages", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		plugin.EXPECT().Stages().Return([]pluginTypes.Stage{pluginTypes.PreRequest})

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true, Stage: pluginTypes.PreRequest},
		}
		_ = m.SetPluginChain("gateway-1", chains)

		result := m.GetChains("gateway-1", pluginTypes.PreRequest)

		assert.Len(t, result, 1)
		assert.Len(t, result[0], 1)
		assert.Equal(t, "test-plugin", result[0][0].Name)
	})

	t.Run("returns chains for stage with allowed stages", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		plugin.EXPECT().Stages().Return(nil) // No fixed stages
		plugin.EXPECT().AllowedStages().Return([]pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PostRequest})

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true, Stage: pluginTypes.PreRequest},
		}
		_ = m.SetPluginChain("gateway-1", chains)

		result := m.GetChains("gateway-1", pluginTypes.PreRequest)

		assert.Len(t, result, 1)
	})

	t.Run("returns empty for non-existent gateway", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		result := m.GetChains("non-existent", pluginTypes.PreRequest)

		assert.Nil(t, result)
	})

	t.Run("filters out plugins not in requested stage", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		plugin.EXPECT().Stages().Return([]pluginTypes.Stage{pluginTypes.PostRequest})

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true, Stage: pluginTypes.PostRequest},
		}
		_ = m.SetPluginChain("gateway-1", chains)

		result := m.GetChains("gateway-1", pluginTypes.PreRequest)

		assert.Len(t, result, 0)
	})
}

func TestManager_ExecuteChain(t *testing.T) {
	t.Run("executes chain successfully", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		plugin.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).Return(&pluginTypes.PluginResponse{StatusCode: 200}, nil)

		_ = m.RegisterPlugin(plugin)

		chain := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true},
		}
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		result, err := m.ExecuteChain(context.Background(), chain, req, resp, newTestCollector())

		assert.NoError(t, err)
		assert.Equal(t, 200, result.StatusCode)
	})

	t.Run("returns error from plugin execution", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")

		pluginErr := &pluginTypes.PluginError{
			Err:        errors.New("execution failed"),
			StatusCode: 500,
		}
		plugin.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).Return(nil, pluginErr)

		_ = m.RegisterPlugin(plugin)

		chain := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true},
		}
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		_, err := m.ExecuteChain(context.Background(), chain, req, resp, newTestCollector())

		assert.Error(t, err)
	})

	t.Run("skips disabled plugins", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		// Execute should NOT be called because plugin is disabled

		_ = m.RegisterPlugin(plugin)

		chain := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: false},
		}
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		_, err := m.ExecuteChain(context.Background(), chain, req, resp, newTestCollector())

		assert.NoError(t, err)
	})

	t.Run("handles empty chain", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		result, err := m.ExecuteChain(context.Background(), nil, req, resp, newTestCollector())

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestManager_ExecuteStage(t *testing.T) {
	t.Run("executes stage with registered chains", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		plugin := pluginMocks.NewPlugin(t)
		plugin.EXPECT().Name().Return("test-plugin")
		plugin.EXPECT().Stages().Return([]pluginTypes.Stage{pluginTypes.PreRequest})
		plugin.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).Return(&pluginTypes.PluginResponse{StatusCode: 200}, nil)

		_ = m.RegisterPlugin(plugin)

		chains := []pluginTypes.PluginConfig{
			{Name: "test-plugin", Enabled: true, Stage: pluginTypes.PreRequest},
		}
		_ = m.SetPluginChain("gateway-1", chains)

		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		result, err := m.ExecuteStage(context.Background(), pluginTypes.PreRequest, "gateway-1", req, resp, newTestCollector())

		assert.NoError(t, err)
		assert.Equal(t, 200, result.StatusCode)
	})

	t.Run("sets stage in request context", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		_, _ = m.ExecuteStage(context.Background(), pluginTypes.PreRequest, "gateway-1", req, resp, newTestCollector())

		assert.Equal(t, pluginTypes.PreRequest, req.Stage)
	})
}

func TestManager_ExecuteChain_Parallel(t *testing.T) {
	t.Run("executes parallel plugins", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		plugin1 := pluginMocks.NewPlugin(t)
		plugin1.EXPECT().Name().Return("plugin-1")
		plugin1.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).Return(&pluginTypes.PluginResponse{StatusCode: 200}, nil)

		plugin2 := pluginMocks.NewPlugin(t)
		plugin2.EXPECT().Name().Return("plugin-2")
		plugin2.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).Return(&pluginTypes.PluginResponse{StatusCode: 200}, nil)

		_ = m.RegisterPlugin(plugin1)
		_ = m.RegisterPlugin(plugin2)

		chain := []pluginTypes.PluginConfig{
			{Name: "plugin-1", Enabled: true, Parallel: true, Priority: 1},
			{Name: "plugin-2", Enabled: true, Parallel: true, Priority: 1},
		}
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		result, err := m.ExecuteChain(context.Background(), chain, req, resp, newTestCollector())

		assert.NoError(t, err)
		assert.Equal(t, 200, result.StatusCode)
	})
}

func TestManager_ExecuteChain_Priority(t *testing.T) {
	t.Run("executes plugins in priority order", func(t *testing.T) {
		m := newManagerForTesting(newTestLogger())

		executionOrder := make([]string, 0)

		plugin1 := pluginMocks.NewPlugin(t)
		plugin1.EXPECT().Name().Return("plugin-low-priority")
		plugin1.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).RunAndReturn(func(
			ctx context.Context,
			cfg pluginTypes.PluginConfig,
			req *types.RequestContext,
			resp *types.ResponseContext,
			evtCtx *metrics.EventContext,
		) (*pluginTypes.PluginResponse, error) {
			executionOrder = append(executionOrder, "plugin-low-priority")
			return &pluginTypes.PluginResponse{StatusCode: 200}, nil
		})

		plugin2 := pluginMocks.NewPlugin(t)
		plugin2.EXPECT().Name().Return("plugin-high-priority")
		plugin2.EXPECT().Execute(
			mock.Anything,
			mock.AnythingOfType("types.PluginConfig"),
			mock.AnythingOfType("*types.RequestContext"),
			mock.AnythingOfType("*types.ResponseContext"),
			mock.Anything,
		).RunAndReturn(func(
			ctx context.Context,
			cfg pluginTypes.PluginConfig,
			req *types.RequestContext,
			resp *types.ResponseContext,
			evtCtx *metrics.EventContext,
		) (*pluginTypes.PluginResponse, error) {
			executionOrder = append(executionOrder, "plugin-high-priority")
			return &pluginTypes.PluginResponse{StatusCode: 200}, nil
		})

		_ = m.RegisterPlugin(plugin1)
		_ = m.RegisterPlugin(plugin2)

		chain := []pluginTypes.PluginConfig{
			{Name: "plugin-low-priority", Enabled: true, Priority: 10},
			{Name: "plugin-high-priority", Enabled: true, Priority: 1},
		}
		req := &types.RequestContext{}
		resp := &types.ResponseContext{}

		_, err := m.ExecuteChain(context.Background(), chain, req, resp, newTestCollector())

		assert.NoError(t, err)
		assert.Equal(t, []string{"plugin-high-priority", "plugin-low-priority"}, executionOrder)
	})
}

// mockPlugin is a simple test implementation of pluginiface.Plugin
type mockPlugin struct {
	name          string
	stages        []pluginTypes.Stage
	allowedStages []pluginTypes.Stage
	validateErr   error
}

func (p *mockPlugin) Name() string {
	return p.name
}

func (p *mockPlugin) Stages() []pluginTypes.Stage {
	return p.stages
}

func (p *mockPlugin) AllowedStages() []pluginTypes.Stage {
	return p.allowedStages
}

func (p *mockPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	return &pluginTypes.PluginResponse{StatusCode: 200}, nil
}

func (p *mockPlugin) ValidateConfig(config pluginTypes.PluginConfig) error {
	return p.validateErr
}

func (p *mockPlugin) RequiredPlugins() []string {
	return nil
}

var _ pluginiface.Plugin = (*mockPlugin)(nil)

