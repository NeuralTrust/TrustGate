package neuraltrust_guardrail_test

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
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_guardrail"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestTrustGateGuardrailPlugin_ValidateConfig(t *testing.T) {
	plugin := &neuraltrust_guardrail.NeuralTrustGuardrailPlugin{}

	validCfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"toxicity":  map[string]interface{}{"threshold": 0.5, "enabled": true},
			"jailbreak": map[string]interface{}{"threshold": 0.3, "enabled": true},
		},
	}
	invalidCfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"toxicity": map[string]interface{}{"threshold": 1.5},
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validCfg))
	assert.Error(t, plugin.ValidateConfig(invalidCfg))
}

func TestTrustGateGuardrailPlugin_Execute_JailbreakSafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	// We don't actually use the embedding service in this test, but we need to mock it
	// to avoid nil pointer dereference
	embeddingLocatorMock.On("GetService", mock.Anything).Return(embeddingCreatorMock)

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.9, "enabled": true},
		},
	}

	jbResp := neuraltrust_guardrail.FirewallResponse{
		Flagged: false,
		Scores:  neuraltrust_guardrail.FirewallScores{MaliciousPrompt: 0.1},
		Prompt:  neuraltrust_guardrail.FirewallPrompt{MaliciousPrompt: false},
	}
	respBytes, err := json.Marshal(jbResp)
	assert.NoError(t, err)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
	}
	mockClient.On("Do", mock.Anything).Return(mockResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"safe"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
}

func TestTrustGateGuardrailPlugin_Execute_JailbreakUnsafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	// We don't actually use the embedding service in this test, but we need to mock it
	// to avoid nil pointer dereference
	embeddingLocatorMock.On("GetService", mock.Anything).Return(embeddingCreatorMock)

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.5, "enabled": true},
		},
	}

	jbResp := neuraltrust_guardrail.FirewallResponse{
		Flagged: true,
		Scores:  neuraltrust_guardrail.FirewallScores{MaliciousPrompt: 0.8},
		Prompt:  neuraltrust_guardrail.FirewallPrompt{MaliciousPrompt: true},
	}
	respBytes, err := json.Marshal(jbResp)
	assert.NoError(t, err)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
	}
	mockClient.On("Do", mock.Anything).Return(mockResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"unsafe jailbreak attempt"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jailbreak: score 0.80 exceeded threshold 0.50")

	assert.Nil(t, pluginResp)
}

func TestTrustGateGuardrailPlugin_Execute_ToxicitySafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	// We don't actually use the embedding service in this test, but we need to mock it
	// to avoid nil pointer dereference
	embeddingLocatorMock.On("GetService", mock.Anything).Return(embeddingCreatorMock)

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"toxicity": map[string]interface{}{"threshold": 0.7, "enabled": true},
		},
	}

	toxResp := neuraltrust_guardrail.ToxicityResponse{
		Flagged: false,
		Scores:  neuraltrust_guardrail.ToxicityScores{ToxicPrompt: 0.2},
		Prompt:  neuraltrust_guardrail.ToxicityPrompt{ToxicPrompt: false},
	}
	respBytes, err := json.Marshal(toxResp)
	assert.NoError(t, err)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
	}
	mockClient.On("Do", mock.Anything).Return(mockResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"non-toxic content"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
}

func TestTrustGateGuardrailPlugin_Execute_ToxicityUnsafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)
	embeddingRepositoryMock := new(mocks.EmbeddingRepository)
	embeddingLocatorMock := new(mocks.EmbeddingServiceLocator)
	embeddingCreatorMock := new(mocks.Creator)

	// We don't actually use the embedding service in this test, but we need to mock it
	// to avoid nil pointer dereference
	embeddingLocatorMock.On("GetService", mock.Anything).Return(embeddingCreatorMock)

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"toxicity": map[string]interface{}{"threshold": 0.5, "enabled": true},
		},
	}

	toxResp := neuraltrust_guardrail.ToxicityResponse{
		Flagged: true,
		Scores:  neuraltrust_guardrail.ToxicityScores{ToxicPrompt: 0.8},
		Prompt:  neuraltrust_guardrail.ToxicityPrompt{ToxicPrompt: true},
	}
	respBytes, err := json.Marshal(toxResp)
	assert.NoError(t, err)
	mockResp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
	}
	mockClient.On("Do", mock.Anything).Return(mockResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"text":"toxic content"}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "toxicity: score 0.80 exceeded threshold 0.50")

	assert.Nil(t, pluginResp)
}

func TestTrustGateGuardrailPlugin_Execute_ModerationSafe(t *testing.T) {
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

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_samples":      []string{"bad content"},
				"deny_topic_action": "block",
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

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
}

func TestTrustGateGuardrailPlugin_Execute_ModerationUnsafe(t *testing.T) {
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
			},
		}, nil)
	embeddingRepositoryMock.On("StoreWithHMSet", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)

	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
		embeddingRepositoryMock,
		embeddingLocatorMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"moderation": map[string]interface{}{
				"threshold":         0.7,
				"enabled":           true,
				"deny_samples":      []string{"bad content"},
				"deny_topic_action": "block",
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

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewCollector("", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "content blocked: with similarity score 0.9")
	assert.Nil(t, pluginResp)
}
