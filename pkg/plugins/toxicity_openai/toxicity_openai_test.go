package toxicity_openai_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_openai"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewToxicityOpenAIPlugin(t *testing.T) {
	plugin := toxicity_openai.NewToxicityOpenAIPlugin(logrus.New(), &http.Client{})
	assert.NotNil(t, plugin)
	assert.Implements(t, (*pluginiface.Plugin)(nil), plugin)
}

func TestToxicityOpenAIPlugin_ValidateConfig(t *testing.T) {
	plugin := toxicity_openai.NewToxicityOpenAIPlugin(logrus.New(), &http.Client{})

	validConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"openai_key": "apikey",
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Toxic content detected",
			},
		},
	}

	invalidConfig := types.PluginConfig{
		Settings: map[string]interface{}{},
	}

	assert.NoError(t, plugin.ValidateConfig(validConfig))
	assert.Error(t, plugin.ValidateConfig(invalidConfig))
}

func TestToxicityOpenAIPlugin_ValidateConfig_InvalidKey(t *testing.T) {
	plugin := toxicity_openai.NewToxicityOpenAIPlugin(logrus.New(), &http.Client{})

	validConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Toxic content detected",
			},
		},
	}

	assert.Error(t, plugin.ValidateConfig(validConfig))
}

func TestToxicityOpenAIPlugin_Execute_Success(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_openai.NewToxicityOpenAIPlugin(logger, mockClient)

	cf := types.PluginConfig{
		Settings: map[string]interface{}{
			"openai_key": "test_key",
			"actions":    map[string]interface{}{"type": "alert", "message": "Toxicity detected"},
		},
	}

	reqBody := toxicity_openai.RequestBody{
		Messages: []toxicity_openai.Message{
			{
				Role:    "user",
				Content: []toxicity_openai.ContentItem{{Type: "text", Text: "test"}},
			},
		},
	}
	reqBytes, _ := json.Marshal(reqBody)
	request := &types.RequestContext{Body: reqBytes}
	response := &types.ResponseContext{}

	serverResponse := toxicity_openai.OpenAIModerationResponse{
		Results: []toxicity_openai.ModerationResult{{CategoryScores: map[string]float64{"hate": 0.4}}},
	}

	serverResponseBytes, _ := json.Marshal(serverResponse)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	resp, err := plugin.Execute(context.Background(), cf, request, response)

	assert.NoError(t, err)
	assert.Equal(t, "Content is safe", resp.Message)
}

func TestToxicityOpenAIPlugin_Execute_FlaggedContent(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_openai.NewToxicityOpenAIPlugin(logger, mockClient)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"openai_key": "test-key",
			"thresholds": map[string]interface{}{
				"hate": 0.8,
			},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Toxic content detected",
			},
		},
	}

	req := &types.RequestContext{Body: []byte(`{"messages": [{"role": "user", "content": [{"type": "text", "text": "hate speech"}]}]}`)}
	resp := &types.ResponseContext{}

	serverResponse := toxicity_openai.OpenAIModerationResponse{
		Results: []toxicity_openai.ModerationResult{{
			Flagged:                   true,
			Categories:                map[string]bool{"hate": true},
			CategoryScores:            map[string]float64{"hate": 0.9},
			CategoryAppliedInputTypes: map[string][]string{"hate": {"text"}},
		}},
	}

	serverResponseBytes, _ := json.Marshal(serverResponse)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Toxic content detected")
}
