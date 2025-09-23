package neuraltrust_jailbreak_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/neuraltrust_jailbreak"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNeuralTrustJailbreakPlugin_ValidateConfig(t *testing.T) {
	plugin := &neuraltrust_jailbreak.NeuralTrustJailbreakPlugin{}

	validCfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.3},
		},
	}
	invalidCfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 1.5},
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validCfg))
	assert.Error(t, plugin.ValidateConfig(invalidCfg))
}

func TestNeuralTrustJailbreakPlugin_Execute_JailbreakSafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.9},
		},
	}

	jbResp := neuraltrust_jailbreak.FirewallResponse{
		Flagged: false,
		Scores:  neuraltrust_jailbreak.FirewallScores{MaliciousPrompt: 0.1},
		Prompt:  neuraltrust_jailbreak.FirewallPrompt{MaliciousPrompt: false},
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

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
}

func TestNeuralTrustJailbreakPlugin_Execute_JailbreakUnsafe(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak": map[string]interface{}{"threshold": 0.5},
		},
	}

	jbResp := neuraltrust_jailbreak.FirewallResponse{
		Flagged: true,
		Scores:  neuraltrust_jailbreak.FirewallScores{MaliciousPrompt: 0.8},
		Prompt:  neuraltrust_jailbreak.FirewallPrompt{MaliciousPrompt: true},
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

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "jailbreak: score 0.80 exceeded threshold 0.50")

	assert.Nil(t, pluginResp)
}

func TestNeuralTrustJailbreakPlugin_Execute_WithMappingFieldArray(t *testing.T) {
	mockClient := new(mocks.MockHTTPClient)
	fingerPrintTrackerMock := new(mocks.Tracker)

	plugin := neuraltrust_jailbreak.NewNeuralTrustJailbreakPlugin(
		logrus.New(),
		mockClient,
		fingerPrintTrackerMock,
	)

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"jailbreak":     map[string]interface{}{"threshold": 0.9},
			"mapping_field": "messages[-1].content",
		},
	}

	jbResp := neuraltrust_jailbreak.FirewallResponse{
		Flagged: false,
		Scores:  neuraltrust_jailbreak.FirewallScores{MaliciousPrompt: 0.1},
		Prompt:  neuraltrust_jailbreak.FirewallPrompt{MaliciousPrompt: false},
	}
	respBytes, err := json.Marshal(jbResp)
	assert.NoError(t, err)
	mockResp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(respBytes))}
	mockClient.On("Do", mock.Anything).Return(mockResp, nil).Once()

	req := &types.RequestContext{Body: []byte(`{"messages":[{"content":"hello"},{"content":"world"}]}`)}
	res := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res, metrics.NewEventContext("", "", nil))
	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
}
