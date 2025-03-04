package toxicity_azure_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/toxicity_azure"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func TestToxicityAzurePlugin_Name(t *testing.T) {
	plugin := &toxicity_azure.ToxicityAzurePlugin{}
	assert.Equal(t, "toxicity_azure", plugin.Name())
}

func TestToxicityAzurePlugin_Stages(t *testing.T) {
	plugin := &toxicity_azure.ToxicityAzurePlugin{}
	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.Stages())
}

func TestToxicityAzurePlugin_AllowedStages(t *testing.T) {
	plugin := &toxicity_azure.ToxicityAzurePlugin{}
	assert.Equal(t, []types.Stage{types.PreRequest}, plugin.AllowedStages())
}

func TestToxicityAzurePlugin_ValidateConfig(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_azure.NewToxicityAzurePlugin(logger, mockClient)

	validConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"api_key": "apikey",
			"endpoints": map[string]interface{}{
				"text": "https://test.azure.com/text",
			},
			"actions": map[string]interface{}{
				"type":    "alert",
				"message": "Content flagged",
			},
		},
	}

	invalidConfig := types.PluginConfig{
		Settings: map[string]interface{}{},
	}

	t.Run("Valid Configuration", func(t *testing.T) {
		err := plugin.ValidateConfig(validConfig)
		assert.NoError(t, err)
	})

	t.Run("Invalid Configuration", func(t *testing.T) {
		err := plugin.ValidateConfig(invalidConfig)
		assert.Error(t, err)
	})
}

func TestToxicityAzurePlugin_ValidateConfig_InvalidApiKey(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_azure.NewToxicityAzurePlugin(logger, mockClient)

	validConfig := types.PluginConfig{
		Settings: map[string]interface{}{
			"api_key": "",
			"endpoints": map[string]interface{}{
				"text": "https://test.azure.com/text",
			},
			"actions": map[string]interface{}{
				"type":    "alert",
				"message": "Content flagged",
			},
		},
	}

	err := plugin.ValidateConfig(validConfig)
	assert.Error(t, err)
}

func TestToxicityAzurePlugin_Execute_Success(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_azure.NewToxicityAzurePlugin(logger, mockClient)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"api_key": "test-key",
			"endpoints": map[string]interface{}{
				"text": "https://test.azure.com/text",
			},
			"content_types": []map[string]interface{}{
				{
					"type": "text",
					"path": "text",
				},
			},
		},
	}

	req := &types.RequestContext{Body: []byte(`{"text": "hello"}`)}
	resp := &types.ResponseContext{}

	serverResponse := toxicity_azure.AzureResponse{
		CategoriesAnalysis: []struct {
			Category string `json:"category"`
			Severity int    `json:"severity"`
		}{{Category: "Hate", Severity: 1}},
	}

	serverResponseBytes, _ := json.Marshal(serverResponse)
	mockResp := io.NopCloser(bytes.NewReader(serverResponseBytes))

	httpResponse := &http.Response{
		StatusCode: http.StatusOK,
		Body:       mockResp,
	}

	mockClient.On("Do", mock.Anything).Return(httpResponse, nil).Once()

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.NotNil(t, pluginResponse)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, pluginResponse.StatusCode)
	mockClient.AssertExpectations(t)
}

func TestToxicityAzurePlugin_Execute_FlaggedContent(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	logger := logrus.New()
	plugin := toxicity_azure.NewToxicityAzurePlugin(logger, mockClient)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"api_key": "test-key",
			"endpoints": map[string]interface{}{
				"text": "https://test.azure.com/text",
			},
			"category_severity": map[string]interface{}{
				"Hate": 2,
			},
			"actions": map[string]interface{}{
				"type":    "reject",
				"message": "Toxic content detected",
			},
			"content_types": []map[string]interface{}{
				{
					"type": "text",
					"path": "text",
				},
			},
		},
	}

	req := &types.RequestContext{Body: []byte(`{"text": "hate speech"}`)}
	resp := &types.ResponseContext{}

	serverResponse := toxicity_azure.AzureResponse{
		CategoriesAnalysis: []struct {
			Category string `json:"category"`
			Severity int    `json:"severity"`
		}{{Category: "Hate", Severity: 3}},
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
	mockClient.AssertExpectations(t)
}
