package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdatePluginsHandler_GatewaySuccess(t *testing.T) {
	defer RunTest(t, "UpdatePlugins", time.Now())()
	// Create gateway with one plugin
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Update Plugins Gateway",
		"subdomain": fmt.Sprintf("update-plugins-%d", time.Now().UnixNano()),
		"required_plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"allowed_origins": []string{"*"},
					"allowed_methods": []string{"GET", "POST"},
					"allowed_headers": []string{"Content-Type"},
					"max_age":         "600s",
				},
			},
		},
	})

	// Read back gateway to get plugin ID
	status, getResp := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)

	requiredPlugins, ok := getResp["required_plugins"].([]interface{})
	assert.True(t, ok)
	assert.NotEmpty(t, requiredPlugins)

	var pluginID string
	for _, p := range requiredPlugins {
		if m, ok := p.(map[string]interface{}); ok {
			if m["name"] == "cors" {
				if id, ok := m["id"].(string); ok {
					pluginID = id
					break
				}
			}
		}
	}
	if pluginID == "" {
		t.Fatalf("cors plugin id not found on gateway")
	}

	// Update plugin by ID (preserve id & name; change enabled, priority, and settings)
	payload := map[string]interface{}{
		"type": "gateway",
		"id":   gatewayID,
		"plugins": []map[string]interface{}{
			{
				"id":       pluginID,
				"enabled":  false,
				"priority": 5,
				"settings": map[string]interface{}{
					"allowed_origins": []string{"https://example.com"},
					"allowed_methods": []string{"GET"},
					"allowed_headers": []string{"Authorization"},
					"max_age":         "120s",
				},
			},
		},
	}
	status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNoContent, status)

	// Verify changes
	status, getResp = sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)

	requiredPlugins, ok = getResp["required_plugins"].([]interface{})
	assert.True(t, ok)
	var found bool
	for _, p := range requiredPlugins {
		m, ok := p.(map[string]interface{})
		assert.True(t, ok)
		idStr, ok := m["id"].(string)
		assert.True(t, ok)
		if idStr == pluginID {
			found = true
			assert.Equal(t, "cors", m["name"])      // name preserved
			assert.Equal(t, false, m["enabled"])    // updated
			assert.EqualValues(t, 5, m["priority"]) // updated
			if settings, ok := m["settings"].(map[string]interface{}); ok {
				ao, ok := settings["allowed_origins"].([]interface{})
				assert.True(t, ok)
				assert.ElementsMatch(t, []interface{}{"https://example.com"}, ao)
				am, ok := settings["allowed_methods"].([]interface{})
				assert.True(t, ok)
				assert.ElementsMatch(t, []interface{}{"GET"}, am)
				ah, ok := settings["allowed_headers"].([]interface{})
				assert.True(t, ok)
				assert.ElementsMatch(t, []interface{}{"Authorization"}, ah)
				assert.Equal(t, "120s", settings["max_age"])
			}
		}
	}
	assert.True(t, found, "updated plugin not found in gateway")
}

func TestUpdatePluginsHandler_GatewayPluginNotFound(t *testing.T) {
	defer RunTest(t, "UpdatePlugins", time.Now())()
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Update Plugins Not Found",
		"subdomain": fmt.Sprintf("update-plugins-nf-%d", time.Now().UnixNano()),
	})

	payload := map[string]interface{}{
		"type": "gateway",
		"id":   gatewayID,
		"plugins": []map[string]interface{}{
			{"id": "00000000-0000-0000-0000-000000000000", "enabled": true},
		},
	}
	status, resp := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNotFound, status)
	if msg, ok := resp["error"].(string); ok {
		assert.Contains(t, msg, "plugin not found")
	}
}
