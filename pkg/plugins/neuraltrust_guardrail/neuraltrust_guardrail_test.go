package neuraltrust_guardrail_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/mocks"
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
	plugin := neuraltrust_guardrail.NewNeuralTrustGuardrailPlugin(logrus.New(), mockClient, fingerPrintTrackerMock)

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

	pluginResp, err := plugin.Execute(context.Background(), cfg, req, res)

	assert.NoError(t, err)
	assert.NotNil(t, pluginResp)
	assert.Equal(t, 200, pluginResp.StatusCode)
	assert.Equal(t, "prompt content is safe", pluginResp.Message)
}
