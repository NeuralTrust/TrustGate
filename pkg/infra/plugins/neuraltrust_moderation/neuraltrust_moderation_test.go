package neuraltrust_moderation_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	fingerprintMocks "github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint/mocks"
	firewallMocks "github.com/NeuralTrust/TrustGate/pkg/infra/firewall/mocks"
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)
	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
	)

	assert.Equal(t, "neuraltrust_moderation", plugin.Name())
}

func TestNeuralTrustModerationPlugin_RequiredPlugins(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)
	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
	)

	assert.Empty(t, plugin.RequiredPlugins())
}

func TestNeuralTrustModerationPlugin_Stages(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
	)

	assert.Equal(t, []plugintypes.Stage{plugintypes.PreRequest}, plugin.Stages())
}

func TestNeuralTrustModerationPlugin_AllowedStages(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
	)

	assert.Equal(t, []plugintypes.Stage{plugintypes.PreRequest}, plugin.AllowedStages())
}

func TestNeuralTrustModerationPlugin_ValidateConfig(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
	)

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
					"enabled":  true,
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
					"enabled":  true,
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

	t.Run("Valid Configuration - Observe Mode", func(t *testing.T) {
		validConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"keyreg_moderation": map[string]interface{}{
					"enabled":              true,
					"similarity_threshold": 0.8,
					"keywords":             []string{"password"},
					"actions": map[string]interface{}{
						"type":    "block",
						"message": "blocked",
					},
				},
				"mode": "observe",
			},
		}
		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Valid Configuration - Enforce Mode", func(t *testing.T) {
		validConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"keyreg_moderation": map[string]interface{}{
					"enabled":              true,
					"similarity_threshold": 0.8,
					"keywords":             []string{"password"},
					"actions": map[string]interface{}{
						"type":    "block",
						"message": "blocked",
					},
				},
				"mode": "enforce",
			},
		}
		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration - Invalid Mode", func(t *testing.T) {
		invalidConfig := plugintypes.PluginConfig{
			Settings: map[string]interface{}{
				"keyreg_moderation": map[string]interface{}{
					"enabled":              true,
					"similarity_threshold": 0.8,
					"keywords":             []string{"password"},
					"actions": map[string]interface{}{
						"type":    "block",
						"message": "blocked",
					},
				},
				"mode": "invalid_mode",
			},
		}
		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mode must be either observe or enforce")
	})
}

func TestNeuralTrustModerationPlugin_Execute_KeyRegSafe(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)
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
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)
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
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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

func TestNeuralTrustModerationPlugin_Execute_ObserveMode_Returns200(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
			"mode": "observe",
		},
	}

	// Content contains blocked keyword but mode is observe
	req := &types.RequestContext{
		Body:      []byte(`my password is 12345`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	// In observe mode, should return 200 instead of 403
	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_EnforceMode_Returns403(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)

	plugin := neuraltrust_moderation.NewNeuralTrustModerationPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		providerLocatorMock,
		firewallFactoryMock,
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
			"mode": "enforce",
		},
	}

	// Content contains blocked keyword with enforce mode
	req := &types.RequestContext{
		Body:      []byte(`my password is 12345`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	// In enforce mode, should return error with 403
	assert.Error(t, err)
	assert.Nil(t, pluginResp)
	assert.Contains(t, err.Error(), "content blocked")

	var pluginError *plugintypes.PluginError
	ok := errors.As(err, &pluginError)
	assert.True(t, ok, "expected PluginError")
	assert.Equal(t, 403, pluginError.StatusCode)
}

func TestNeuralTrustModerationPlugin_Execute_LLMModeration_ObserveMode(t *testing.T) {
	mockClient := new(httpxMocks.MockHTTPClient)
	fingerPrintTrackerMock := new(fingerprintMocks.Tracker)
	providerLocatorMock := new(providerMocks.ProviderLocator)
	firewallFactoryMock := new(firewallMocks.ClientFactory)
	clientMock := new(clientMocks.Client)

	// Setup mock response for LLM moderation (flagged content)
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
		providerLocatorMock,
		firewallFactoryMock,
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
			"mode": "observe",
		},
	}

	req := &types.RequestContext{
		Body:      []byte(`{"text":"Let's discuss the upcoming elections"}`),
		GatewayID: "test-gateway",
	}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	// In observe mode, should return 200 instead of 403
	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}
