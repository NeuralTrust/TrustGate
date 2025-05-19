package neuraltrust_moderation_test

import (
	"context"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_moderation"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNeuralTrustModerationPlugin_Name(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	assert.Equal(t, "neuraltrust_moderation", plugin.Name())
}

func TestNeuralTrustModerationPlugin_RequiredPlugins(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	assert.Empty(t, plugin.RequiredPlugins())
}

func TestNeuralTrustModerationPlugin_Stages(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.Stages())
}

func TestNeuralTrustModerationPlugin_AllowedStages(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.AllowedStages())
}

func TestNeuralTrustModerationPlugin_ValidateConfig(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	t.Run("Valid Configuration", func(t *testing.T) {
		validConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
				"moderation": map[string]interface{}{
					"threshold":         0.7,
					"enabled":           true,
					"deny_topic_action": "block",
					"deny_samples":      []string{"bad content"},
					"embedding_config": map[string]interface{}{
						"provider": "openai",
						"model":    "text-embedding-ada-002",
						"credentials": map[string]interface{}{
							"header_name":  "Authorization",
							"header_value": "Bearer test-token",
						},
					},
				},
			},
		}

		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration - Missing Threshold", func(t *testing.T) {
		invalidConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
				"enabled": true,
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("Invalid Configuration - Invalid Threshold", func(t *testing.T) {
		invalidConfig := types.PluginConfig{
			Settings: map[string]interface{}{
				"credentials": map[string]interface{}{
					"base_url": "https://api.neuraltrust.ai",
					"token":    "test-token",
				},
				"threshold": 1.5, // Invalid: > 1
				"enabled":   true,
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})
}

func TestNeuralTrustModerationPlugin_Execute_ModerationSafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{
			EntityID:  "test-entity",
			Value:     []float64{0.1, 0.2, 0.3},
			CreatedAt: time.Now(),
		}, nil)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustGuardRailIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("Search", mock.Anything, common.NeuralTrustGuardRailIndexName, mock.Anything, mock.Anything).
		Return([]embedding.SearchResult{}, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"header_name":  "Authorization",
						"header_value": "Bearer test-token",
					},
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"safe content"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_ModerationUnsafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{
			EntityID:  "test-entity",
			Value:     []float64{0.1, 0.2, 0.3},
			CreatedAt: time.Now(),
		}, nil)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustGuardRailIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("Search", mock.Anything, common.NeuralTrustGuardRailIndexName, mock.Anything, mock.Anything).
		Return([]embedding.SearchResult{
			{
				Key:   "deny-sample-1",
				Score: 0.9, // High similarity score
				Data:  "bad content",
			},
		}, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"header_name":  "Authorization",
						"header_value": "Bearer test-token",
					},
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"unsafe content similar to deny samples"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "content blocked: with similarity score 0.9")
	assert.Nil(t, pluginResp)
}

func TestNeuralTrustModerationPlugin_Execute_EmbeddingError(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, assert.AnError)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustGuardRailIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"header_name":  "Authorization",
						"header_value": "Bearer test-token",
					},
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"content"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
}

func TestNeuralTrustModerationPlugin_Execute_DisabledPlugin(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"credentials": map[string]interface{}{
				"base_url": "https://api.neuraltrust.ai",
				"token":    "test-token",
			},
			"moderation": map[string]interface{}{
				"threshold": 0.7,
				"enabled":   false,
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"content"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}
