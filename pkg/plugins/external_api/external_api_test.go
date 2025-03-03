package external_api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/external_api"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNewExternalApiPlugin(t *testing.T) {
	plugin := external_api.NewExternalApiPlugin(&http.Client{})
	assert.NotNil(t, plugin)
	assert.Implements(t, (*pluginiface.Plugin)(nil), plugin)
}

func TestExternalApiPlugin_ValidateConfig(t *testing.T) {
	plugin := external_api.NewExternalApiPlugin(&http.Client{})

	validConfig := types.PluginConfig{
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"endpoint": "https://example.com",
			"headers": map[string]interface{}{
				"Authorization": "Bearer token",
			},
			"field_maps": []interface{}{
				map[string]interface{}{"source": "input", "destination": "output"},
			},
			"conditions": []interface{}{
				map[string]interface{}{"field": "status", "operator": "eq", "value": "success", "stop_processing": true, "message": "Validation failed"},
			},
			"timeout": "10s",
		},
	}

	assert.NoError(t, plugin.ValidateConfig(validConfig))
}

func TestExternalApiPlugin_Execute_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"validation": "success"}`))
	}))
	defer ts.Close()

	plugin := external_api.NewExternalApiPlugin(ts.Client())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"endpoint": ts.URL,
			"method":   "POST",
		},
	}

	req := &types.RequestContext{Body: []byte(`{"input": "test"}`)}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.NotNil(t, pluginResponse)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, pluginResponse.StatusCode)
}

func TestExternalApiPlugin_Execute_ConditionMatching(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer ts.Close()

	plugin := external_api.NewExternalApiPlugin(ts.Client())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"endpoint": ts.URL,
			"conditions": []interface{}{
				map[string]interface{}{
					"field":           "status",
					"operator":        "eq",
					"value":           "success",
					"stop_processing": true,
					"message":         "Validation failed",
				},
			},
		},
	}

	req := &types.RequestContext{}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)
	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Validation failed")
}

func TestExternalApiPlugin_Execute_Failure(t *testing.T) {

	plugin := external_api.NewExternalApiPlugin(&http.Client{Timeout: time.Millisecond})

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"endpoint": "http://127.0.0.1:9999", // Non-routable address
			"method":   "POST",
		},
	}

	req := &types.RequestContext{Body: []byte(`{"input": "test"}`)}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Nil(t, pluginResponse)
	assert.Error(t, err)
}

func TestExternalApiPlugin_Execute_WithFieldMapping(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&requestBody)

		responseBody, _ := json.Marshal(map[string]interface{}{"status": "success", "mapped": requestBody})
		w.WriteHeader(http.StatusOK)
		w.Write(responseBody)
	}))
	defer ts.Close()

	plugin := external_api.NewExternalApiPlugin(ts.Client())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"endpoint": ts.URL,
			"method":   "POST",
			"field_maps": []interface{}{
				map[string]interface{}{"source": "input", "destination": "output"},
			},
		},
	}

	requestBody := map[string]interface{}{"input": "test_value"}
	bodyBytes, _ := json.Marshal(requestBody)

	req := &types.RequestContext{Body: bodyBytes}
	resp := &types.ResponseContext{}

	pluginResponse, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.NotNil(t, pluginResponse)
	assert.NoError(t, err)

	var responseBody map[string]interface{}
	err = json.Unmarshal(pluginResponse.Body, &responseBody)
	assert.NoError(t, err)
	assert.Equal(t, "test_value", responseBody["mapped"].(map[string]interface{})["output"])
}

func TestExternalApiPlugin_Execute_WithInvalidFieldMapping(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&requestBody)

		responseBody, _ := json.Marshal(map[string]interface{}{"status": "success", "mapped": requestBody})
		w.WriteHeader(http.StatusOK)
		w.Write(responseBody)
	}))
	defer ts.Close()

	plugin := external_api.NewExternalApiPlugin(ts.Client())

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"endpoint": ts.URL,
			"method":   "POST",
			"field_maps": []interface{}{
				map[string]interface{}{"sourc": "input", "destination": "output"},
			},
		},
	}

	requestBody := map[string]interface{}{"input": "test_value"}
	bodyBytes, _ := json.Marshal(requestBody)

	req := &types.RequestContext{Body: bodyBytes}
	resp := &types.ResponseContext{}

	_, err := plugin.Execute(context.Background(), cfg, req, resp)

	assert.Error(t, err)

}

func TestPluginMetadata(t *testing.T) {
	plugin := external_api.NewExternalApiPlugin(&http.Client{})
	assert.Equal(t, "external_api", plugin.Name())
	assert.ElementsMatch(t, []types.Stage{}, plugin.Stages())
	assert.ElementsMatch(t, []types.Stage{types.PreRequest, types.PostResponse}, plugin.AllowedStages())
}
