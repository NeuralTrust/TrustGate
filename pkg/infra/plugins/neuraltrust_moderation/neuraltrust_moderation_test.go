package neuraltrust_moderation_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	embeddingMocks "github.com/NeuralTrust/TrustGate/pkg/domain/embedding/mocks"
	embeddingFactoryMocks "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory/mocks"
	fingerprintMocks "github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint/mocks"
	httpxMocks "github.com/NeuralTrust/TrustGate/pkg/infra/httpx/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/neuraltrust_moderation"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	providerMocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	clientMocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNeuralTrustModerationPlugin_Name(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	assert.Equal(t, "neuraltrust_moderation", plugin.Name())
}

func TestNeuralTrustModerationPlugin_RequiredPlugins(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	assert.Empty(t, plugin.RequiredPlugins())
}

func TestNeuralTrustModerationPlugin_Stages(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	assert.Equal(t, []plugintypes.Stage{plugintypes.PreRequest}, plugin.Stages())
}

func TestNeuralTrustModerationPlugin_AllowedStages(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	assert.Equal(t, []plugintypes.Stage{plugintypes.PreRequest}, plugin.AllowedStages())
}

func TestNeuralTrustModerationPlugin_ValidateConfig(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	t.Run("Valid Configuration", func(t *testing.T) {
		validConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"embedding_moderation": map[string]interface{}{
					"threshold":         0.7,
					"enabled":           true,
					"deny_topic_action": "block",
					"deny_samples":      []string{"bad content"},
					"embedding_config": map[string]interface{}{
						"provider": "openai",
						"model":    "text-embedding-ada-002",
						"credentials": map[string]interface{}{
							"api_key": "test-api-key",
						},
					},
				},
			},
		}

		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration - Missing Threshold", func(t *testing.T) {
		invalidConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"embedding_moderation": map[string]interface{}{
					"enabled": true,
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("Invalid Configuration - Invalid Threshold", func(t *testing.T) {
		invalidConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"embedding_moderation": map[string]interface{}{
					"threshold": 1.5, // Invalid: > 1
					"enabled":   true,
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("Valid Configuration - LLM Provider", func(t *testing.T) {
		validConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"llm_moderation": map[string]interface{}{
					"provider": "openai",
					"model":    "gpt-4",
					"credentials": map[string]interface{}{
						"api_key": "key",
					},
					"instructions": []string{"Be safe"},
				},
			},
		}

		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)

		validConfig = plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"llm_moderation": map[string]interface{}{
					"provider": "google",
					"model":    "gemini-pro",
					"credentials": map[string]interface{}{
						"api_key": "key",
					},
					"instructions": []string{"Be safe"},
				},
			},
		}

		err = plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration - LLM Provider", func(t *testing.T) {
		invalidConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"llm_moderation": map[string]interface{}{
					"provider": "invalid-provider", // Invalid: not openai or gemini
					"model":    "some-model",
					"credentials": map[string]interface{}{
						"header_name":  "Authorization",
						"header_value": "Bearer test-token",
					},
					"instructions": []string{"Be safe"},
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})

	t.Run("Invalid Configuration - Empty LLM Model", func(t *testing.T) {
		invalidConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"llm_moderation": map[string]interface{}{
					"provider": "openai",
					"model":    "", // Invalid: empty model
					"credentials": map[string]interface{}{
						"header_name":  "Authorization",
						"header_value": "Bearer test-token",
					},
					"instructions": []string{"Be safe"},
				},
			},
		}

		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})
}

func TestNeuralTrustModerationPlugin_Execute_ModerationSafe(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(embeddingMocks.Creator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{
			EntityID:  "test-entity",
			Value:     []float64{0.1, 0.2, 0.3},
			CreatedAt: time.Now(),
		}, nil)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("Search", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything, mock.Anything).
		Return([]embedding.SearchResult{}, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"embedding_moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"api_key": "test-api-key",
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
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(embeddingMocks.Creator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{
			EntityID:  "test-entity",
			Value:     []float64{0.1, 0.2, 0.3},
			CreatedAt: time.Now(),
		}, nil)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("Search", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything, mock.Anything).
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
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"embedding_moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"api_key": "test-api-key",
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
	assert.Contains(t, err.Error(), "content blocked: similarity score")
	assert.Nil(t, pluginResp)
}

func TestNeuralTrustModerationPlugin_Execute_WithMappingFieldArray(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	creatorMock := new(embeddingMocks.Creator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"embedding_moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"api_key": "test-api-key",
					},
				},
			},
			"mapping_field": "messages[-1].content",
		},
	}

	// Mock embedding flow minimal to return safe
	embeddingLocatorMock.On("GetService", "openai").Return(creatorMock, nil)
	creatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{EntityID: "test", Value: []float64{0.1}, CreatedAt: time.Now()}, nil)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything).Return(0, nil)
	embeddingRepositoryMock.On("Search", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything, mock.Anything).Return([]embedding.SearchResult{}, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := &types.RequestContext{Body: []byte(`{"messages":[{"content":"hello"},{"content":"world"}]}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))
	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_EmbeddingError(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(embeddingMocks.Creator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	embeddingLocatorMock.On("GetService", "openai").Return(embeddingCreatorMock, nil)
	embeddingCreatorMock.On("Generate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, assert.AnError)
	embeddingRepositoryMock.On("Count", mock.Anything, common.NeuralTrustJailbreakIndexName, mock.Anything).
		Return(0, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"embedding_moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_topic_action": "block",
				"deny_samples":      []string{"bad content"},
				"embedding_config": map[string]interface{}{
					"provider": "openai",
					"model":    "text-embedding-ada-002",
					"credentials": map[string]interface{}{
						"api_key": "test-api-key",
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
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"embedding_moderation": map[string]interface{}{
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

func TestNeuralTrustModerationPlugin_Execute_KeyRegSafe(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret", "api_key"},
				"regex":                []string{"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`safe content without any sensitive information`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_KeyRegKeywordBlocked(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret", "api_key"},
				"regex":                []string{"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`my password is 12345`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")
}

func TestNeuralTrustModerationPlugin_Execute_KeyRegSimilarWordBlocked(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret", "api_key"},
				"regex":                []string{"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`my passw0rd is 12345`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")
}

func TestNeuralTrustModerationPlugin_Execute_KeyRegRegexBlocked(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret", "api_key"},
				"regex":                []string{"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`my email is test@example.com`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")
}

func TestNeuralTrustModerationPlugin_Execute_LLMModeration(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	clientMock := new(clientMocks.Client)

	// Setup mock response for LLM moderation
	llmResponse := neuraltrust_moderation.LLMResponse{
		Topic:            "politics",
		InstructionMatch: "Block if it mentions politics",
		Flagged:          true,
	}
	responseJSON, err := json.Marshal(llmResponse)
	if err != nil {
		t.Fatalf("Failed to marshal LLM response: %v", err)
	}

	// Setup expectations for provider locator and client
	providerLocatorMock.On("Get", "openai").Return(clientMock, nil)
	clientMock.On("Ask", mock.Anything, mock.Anything, mock.Anything).Return(&providers.CompletionResponse{
		ID:       "test-id",
		Model:    "gpt-4",
		Response: string(responseJSON),
		Usage: providers.Usage{
			PromptTokens:     10,
			CompletionTokens: 20,
			TotalTokens:      30,
		},
	}, nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"llm_moderation": map[string]interface{}{
				"provider": "openai",
				"model":    "gpt-4",
				"enabled":  true,
				"credentials": map[string]interface{}{
					"api_key": "test-api-key",
				},
				"instructions": []string{"Block if it mentions politics"},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"Let's discuss the upcoming elections"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")
}

func TestNeuralTrustModerationPlugin_Execute_LLMModerationSafe(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	clientMock := new(clientMocks.Client)

	// Setup mock response for LLM moderation (safe content)
	llmResponse := neuraltrust_moderation.LLMResponse{
		Topic:            "other",
		InstructionMatch: "",
		Flagged:          false,
	}
	responseJSON, err := json.Marshal(llmResponse)
	if err != nil {
		t.Fatalf("Failed to marshal LLM response: %v", err)
	}

	// Setup expectations for provider locator and client
	providerLocatorMock.On("Get", "openai").Return(clientMock, nil)
	clientMock.On("Ask", mock.Anything, mock.Anything, mock.Anything).Return(&providers.CompletionResponse{
		ID:       "test-id",
		Model:    "gpt-4",
		Response: string(responseJSON),
		Usage: providers.Usage{
			PromptTokens:     10,
			CompletionTokens: 20,
			TotalTokens:      30,
		},
	}, nil)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"llm_moderation": map[string]interface{}{
				"provider": "openai",
				"model":    "gpt-4",
				"enabled":  true,
				"credentials": map[string]interface{}{
					"api_key": "test-api-key",
				},
				"instructions": []string{"Block if it mentions politics"},
			},
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"This is a safe message about technology"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_WithMessages_KeyRegSafe(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	// Messages should be used instead of Body
	req := &types.RequestContext{
		Body:      []byte(`password secret api_key`), // This would be blocked if used
		Messages:  []string{"safe message 1", "safe message 2"},
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_WithMessages_KeyRegBlocked(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	embeddingRepositoryMock := new(embeddingMocks.Repository)
	embeddingLocatorMock := new(embeddingFactoryMocks.EmbeddingServiceLocator)
	providerLocatorMock := new(providerMocks.ProviderLocator)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
		providerLocatorMock,
	)

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"keyreg_moderation": map[string]interface{}{
				"enabled":              true,
				"similarity_threshold": 0.8,
				"keywords":             []string{"password", "secret"},
				"actions": map[string]interface{}{
					"type":    "block",
					"message": "Content contains sensitive information",
				},
			},
		},
	}

	// Messages contain blocked keyword
	req := &types.RequestContext{
		Body:      []byte(`safe content`), // This is safe but should be ignored
		Messages:  []string{"my password is 12345"},
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")
}

