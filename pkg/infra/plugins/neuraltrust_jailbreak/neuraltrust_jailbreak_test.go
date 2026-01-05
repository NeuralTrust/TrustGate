package neuraltrust_jailbreak_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	firewallmocks "github.com/NeuralTrust/TrustGate/pkg/infra/firewall/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/neuraltrust_jailbreak"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNeuralTrustJailbreakPlugin_ValidateConfig(t *testing.T) {
	plugin := &neuraltrust_jailbreak.NeuralTrustJailbreakPlugin{}

	validCfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.3},
		},
	}
	invalidCfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 1.5},
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validCfg))
	assert.Error(t, plugin.ValidateConfig(invalidCfg))
}

func TestNeuralTrustJailbreakPlugin_Execute_JailbreakSafe(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak": map[string]interface{}{"threshold": 0.9},
		},
	}

	// Mock firewall response with safe content
	jailbreakResp := []firewall.JailbreakResponse{{
		Scores: firewall.JailbreakScores{
			MaliciousPrompt: 0.1, // Below threshold
		},
	}}

	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(jailbreakResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"safe"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustJailbreakPlugin_Execute_JailbreakUnsafe(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak": map[string]interface{}{"threshold": 0.5},
		},
	}

	// Mock firewall response with unsafe content
	jailbreakResp := []firewall.JailbreakResponse{{
		Scores: firewall.JailbreakScores{
			MaliciousPrompt: 0.8, // Above threshold
		},
	}}

	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(jailbreakResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"unsafe jailbreak attempt"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jailbreak: score 0.80 exceeded threshold 0.50")
	assert.Nil(t, pluginResp)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustJailbreakPlugin_Execute_WithMappingFieldArray(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak":     map[string]interface{}{"threshold": 0.9},
			"mapping_field": "messages[-1].content",
		},
	}

	// Mock firewall response with safe content
	jailbreakResp := []firewall.JailbreakResponse{{
		Scores: firewall.JailbreakScores{
			MaliciousPrompt: 0.1, // Below threshold
		},
	}}

	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(jailbreakResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"messages":[{"content":"hello"},{"content":"world"}]}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))
	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustJailbreakPlugin_Execute_FirewallError(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak": map[string]interface{}{"threshold": 0.5},
		},
	}

	// Mock firewall error
	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"test"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustJailbreakPlugin_Execute_FirewallServiceUnavailable(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak": map[string]interface{}{"threshold": 0.5},
		},
	}

	// Mock firewall service unavailable error (ErrFailedFirewallCall)
	firewallError := fmt.Errorf("%w: status %d", firewall.ErrFailedFirewallCall, 503)
	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(nil, firewallError).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"test"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)

	// Verify it's a regular error, not a PluginError
	_, ok := err.(*pluginTypes.PluginError)
	assert.False(t, ok, "expected regular error, not PluginError")
	assert.Contains(t, err.Error(), "firewall request failed")
	assert.Contains(t, err.Error(), "firewall service call failed")

	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustJailbreakPlugin_Execute_FirewallServiceError(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	fingerPrintTrackerMock := new(mocks.Tracker)

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockFirewallFactory,
		fingerPrintTrackerMock,
	)

	cfg := pluginTypes.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"jailbreak": map[string]interface{}{"threshold": 0.5},
		},
	}

	// Mock other firewall error (not ErrFailedFirewallCall)
	otherError := fmt.Errorf("circuit breaker open")
	mockFirewallClient.On("DetectJailbreak", mock.Anything, mock.Anything, mock.Anything).Return(nil, otherError).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"test"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)

	// Verify it's a regular error, not a PluginError
	_, ok := err.(*pluginTypes.PluginError)
	assert.False(t, ok, "expected regular error, not PluginError")
	assert.Contains(t, err.Error(), "failed to call firewall")

	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}
