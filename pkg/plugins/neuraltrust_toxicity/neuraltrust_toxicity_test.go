package neuraltrust_toxicity_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	firewallmocks "github.com/NeuralTrust/TrustGate/pkg/infra/firewall/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_toxicity"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNeuralTrustToxicity_Name(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(logrus.New(), mockTracker, nil)
	assert.Equal(t, "neuraltrust_toxicity", plugin.Name())
}

func TestNeuralTrustToxicity_RequiredPlugins(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(logrus.New(), mockTracker, nil)
	assert.Empty(t, plugin.RequiredPlugins())
}

func TestNeuralTrustToxicity_Stages(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(logrus.New(), mockTracker, nil)
	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.Stages())
}

func TestNeuralTrustToxicity_AllowedStages(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(logrus.New(), mockTracker, nil)
	assert.Equal(t, []types.Stage{types.PreRequest, types.PostRequest}, plugin.AllowedStages())
}

func TestNeuralTrustToxicity_ValidateConfig(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(logger, mockTracker, nil)

	t.Run("Valid Configuration", func(t *testing.T) {
		validConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
				"toxicity": map[string]interface{}{
					"threshold": 0.7,
					"enabled":   true,
				},
			},
		}

		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration - Missing Toxicity", func(t *testing.T) {
		invalidConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "toxicity must be enabled")
	})

	t.Run("Invalid Configuration - Invalid Threshold", func(t *testing.T) {
		invalidConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
				"toxicity": map[string]interface{}{
					"threshold": 1.5, // Invalid: > 1
					"enabled":   true,
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "toxicity threshold must be between 0 and 1")
	})
}

func TestNeuralTrustToxicity_Execute_Success(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{"text": "hello world"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock response with toxicity score below threshold
	toxicityResp := []firewall.ToxicityResponse{{
		Scores: map[string]float64{
			"toxic_prompt": 0.2, // Below threshold
		},
	}}

	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(toxicityResp, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, 200, pluginResponse.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResponse.Message)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_ToxicContent(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{"text": "potentially toxic content"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock response with toxicity score above threshold
	toxicityResp := []firewall.ToxicityResponse{{
		CategoryScores: map[string]float64{
			"toxic_prompt": 0.8, // Above threshold
		},
	}}

	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(toxicityResp, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)
	assert.Contains(t, err.Error(), "score 0.80 exceeded threshold 0.70")
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_WithMappingField(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
			"mapping_field": "messages[-1].content",
		},
	}

	// Request with nested structure
	req := &types.RequestContext{
		Body: []byte(`{
			"messages": [
				{"role": "user", "content": "hello world"}
			]
		}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock response with toxicity score below threshold
	toxicityResp := []firewall.ToxicityResponse{{
		Scores: map[string]float64{
			"toxic_prompt": 0.2, // Below threshold
		},
	}}

	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(toxicityResp, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, 200, pluginResponse.StatusCode)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_PostRequest(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{}`), // Empty request body
		Stage: types.PostRequest,
	}
	resp := &types.ResponseContext{
		Body: []byte(`{"text": "response content"}`),
	}

	// Mock response with toxicity score below threshold
	toxicityResp := []firewall.ToxicityResponse{{
		Scores: map[string]float64{
			"toxic_prompt": 0.2, // Below threshold
		},
	}}

	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(toxicityResp, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, 200, pluginResponse.StatusCode)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_FirewallError(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{"text": "hello world"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock firewall error
	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(nil, assert.AnError).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_FirewallServiceUnavailable(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{"text": "hello world"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock firewall service unavailable error (ErrFailedFirewallCall)
	firewallError := fmt.Errorf("%w: status %d", firewall.ErrFailedFirewallCall, 503)
	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(nil, firewallError).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)

	// Verify it's a regular error, not a PluginError
	_, ok := err.(*types.PluginError)
	assert.False(t, ok, "expected regular error, not PluginError")
	assert.Contains(t, err.Error(), "firewall request failed")
	assert.Contains(t, err.Error(), "firewall service call failed")

	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_FirewallServiceError(t *testing.T) {
	mockFirewallClient := new(firewallmocks.Client)
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
		},
	}

	req := &types.RequestContext{
		Body:  []byte(`{"text": "hello world"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Mock other firewall error (not ErrFailedFirewallCall)
	otherError := fmt.Errorf("circuit breaker open")
	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(nil, otherError).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)

	// Verify it's a regular error, not a PluginError
	_, ok := err.(*types.PluginError)
	assert.False(t, ok, "expected regular error, not PluginError")
	assert.Contains(t, err.Error(), "failed to call firewall")

	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
}

func TestNeuralTrustToxicity_Execute_NotifyGuardrailViolation(t *testing.T) {
	// Create mocks
	mockFirewallClient := new(firewallmocks.Client)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	// Create plugin with the fingerprint tracker
	mockFirewallFactory := new(firewallmocks.ClientFactory)
	mockFirewallFactory.On("Get", "").Return(mockFirewallClient, nil)

	plugin := neuraltrust_toxicity.NewNeuralTrustToxicity(
		logger,
		mockTracker,
		mockFirewallFactory,
	)

	// Create configuration
	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"toxicity": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   true,
			},
			"retention_period": 60,
		},
	}

	// Create request and response
	req := &types.RequestContext{
		Body:  []byte(`{"text": "potentially toxic content"}`),
		Stage: types.PreRequest,
	}
	resp := &types.ResponseContext{}

	// Create a fingerprint
	fp := &fingerprint.Fingerprint{
		UserID:    "test-user",
		Token:     "test-token",
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}
	fpID := fp.ID()

	// Create context with fingerprint ID
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, fpID)

	// Set up mock responses
	toxicityResp := []firewall.ToxicityResponse{{
		CategoryScores: map[string]float64{
			"toxic_prompt": 0.8, // Above threshold
		},
	}}

	// Set up expectations
	mockFirewallClient.On("DetectToxicity", mock.Anything, mock.Anything, mock.Anything).Return(toxicityResp, nil).Once()
	mockTracker.On("GetFingerprint", mock.Anything, fpID).Return(fp, nil).Once()
	mockTracker.On("IncrementMaliciousCount", mock.Anything, fpID, time.Duration(60)*time.Second).Return(nil).Once()

	// Execute the plugin
	pluginResponse, err := plugin.Execute(
		ctx,
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	// Verify results
	assert.Error(t, err)
	assert.Nil(t, pluginResponse)
	assert.Contains(t, err.Error(), "score 0.80 exceeded threshold 0.70")

	// Verify that the mock expectations were met
	mockFirewallClient.AssertExpectations(t)
	mockFirewallFactory.AssertExpectations(t)
	mockTracker.AssertExpectations(t)
}
