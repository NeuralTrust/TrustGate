package toxicity_neuraltrust_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_neuraltrust"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestToxicityNeuralTrust_Name(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logrus.New(), mockTracker, nil)
	assert.Equal(t, "toxicity_neuraltrust", plugin.Name())
}

func TestToxicityNeuralTrust_RequiredPlugins(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logrus.New(), mockTracker, nil)
	assert.Empty(t, plugin.RequiredPlugins())
}

func TestToxicityNeuralTrust_Stages(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logrus.New(), mockTracker, nil)
	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.Stages())
}

func TestToxicityNeuralTrust_AllowedStages(t *testing.T) {
	mockTracker := new(mocks.Tracker)
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logrus.New(), mockTracker, nil)
	assert.Equal(t, []types.Stage{types.PreRequest, types.PostRequest}, plugin.AllowedStages())
}

func TestToxicityNeuralTrust_ValidateConfig(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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

func TestToxicityNeuralTrust_Execute_Success(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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
	serverResponse := map[string]interface{}{
		"scores": map[string]interface{}{
			"toxic_prompt": 0.2, // Below threshold
		},
	}

	serverResponseBytes, err := json.Marshal(serverResponse)
	assert.NoError(t, err)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, http.StatusOK, pluginResponse.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResponse.Message)
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_ToxicContent(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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

	serverResponse := map[string]interface{}{
		"category_scores": map[string]interface{}{
			"toxic_prompt": 0.8,
		},
	}

	serverResponseBytes, err := json.Marshal(serverResponse)
	assert.NoError(t, err)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

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
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_WithMappingField(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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
			"mapping_field": "messages.0.content",
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
	serverResponse := map[string]interface{}{
		"scores": map[string]interface{}{
			"toxic_prompt": 0.2, // Below threshold
		},
	}

	serverResponseBytes, err := json.Marshal(serverResponse)
	assert.NoError(t, err)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, http.StatusOK, pluginResponse.StatusCode)
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_PostRequest(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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
	serverResponse := map[string]interface{}{
		"scores": map[string]interface{}{
			"toxic_prompt": 0.2, // Below threshold
		},
	}

	serverResponseBytes, err := json.Marshal(serverResponse)
	assert.NoError(t, err)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResponse)
	assert.Equal(t, http.StatusOK, pluginResponse.StatusCode)
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_HTTPError(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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

	// Mock HTTP error
	mockClient.On("Do", mock.Anything).Return(nil, assert.AnError).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_InvalidResponse(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(logger, mockTracker, mockClient)

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

	// Invalid JSON response
	mockResp := io.NopCloser(bytes.NewReader([]byte(`invalid json`)))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	assert.Error(t, err)
	assert.Nil(t, pluginResponse)
	assert.Contains(t, err.Error(), "invalid toxicity response")
	mockClient.AssertExpectations(t)
}

func TestToxicityNeuralTrust_Execute_NotifyGuardrailViolation(t *testing.T) {
	// Create mocks
	mockClient := new(mocks.MockHTTPClient)
	mockTracker := new(mocks.Tracker)
	logger := logrus.New()

	// Create plugin with the fingerprint tracker
	plugin := toxicity_neuraltrust.NewToxicityNeuralTrust(
		logger,
		mockTracker,
		mockClient,
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
	serverResponse := map[string]interface{}{
		"category_scores": map[string]interface{}{
			"toxic_prompt": 0.8, // Above threshold
		},
	}

	serverResponseBytes, err := json.Marshal(serverResponse)
	assert.NoError(t, err)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	// Set up expectations
	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()
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
	mockClient.AssertExpectations(t)
	mockTracker.AssertExpectations(t)
}
