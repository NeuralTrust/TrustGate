package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeletePluginsHandler(t *testing.T) {
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Delete Plugins Gateway",
		"subdomain": fmt.Sprintf("del-plugins-%d", time.Now().UnixNano()),
		"required_plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 0,
				"settings": map[string]interface{}{
					"allowed_origins": []string{"*"},
					"allowed_methods": []string{"GET"},
					"allowed_headers": []string{"Content-Type"},
					"max_age":         "60s",
				},
			},
			{
				"name":     "rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"limits": map[string]interface{}{
						"per_ip": map[string]interface{}{"limit": 5, "window": "10s"},
					},
					"actions": map[string]interface{}{"type": "reject"},
				},
			},
		},
	})

	// Get gateway to extract plugin IDs
	status, gatewayResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)
	rp, ok := gatewayResponse["required_plugins"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 2, len(rp), "Expected 2 plugins initially")

	// Extract plugin IDs
	var corsPluginID, rateLimiterPluginID string
	for _, p := range rp {
		if m, ok := p.(map[string]interface{}); ok {
			name := fmt.Sprintf("%v", m["name"])
			id, idOk := m["id"].(string)
			if idOk {
				if name == "cors" {
					corsPluginID = id
				} else if name == "rate_limiter" {
					rateLimiterPluginID = id
				}
			}
		}
	}
	assert.NotEmpty(t, corsPluginID, "CORS plugin ID should not be empty")
	assert.NotEmpty(t, rateLimiterPluginID, "Rate limiter plugin ID should not be empty")

	// Delete CORS plugin via delete handler using plugin ID
	payload := map[string]interface{}{
		"type":       "gateway",
		"id":         gatewayID,
		"plugin_ids": []string{corsPluginID},
	}
	status, _ = sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNoContent, status)

	// Verify CORS removed and rate_limiter remains
	status, response := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)
	rp, ok = response["required_plugins"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 1, len(rp), "Expected 1 plugin after deletion")

	// ensure only rate_limiter remains
	names := make([]string, 0, len(rp))
	ids := make([]string, 0, len(rp))
	for _, p := range rp {
		if m, ok := p.(map[string]interface{}); ok {
			names = append(names, fmt.Sprintf("%v", m["name"]))
			if id, idOk := m["id"].(string); idOk {
				ids = append(ids, id)
			}
		}
	}
	assert.NotContains(t, names, "cors")
	assert.Contains(t, names, "rate_limiter")
	assert.NotContains(t, ids, corsPluginID, "CORS plugin ID should not be present")
	assert.Contains(t, ids, rateLimiterPluginID, "Rate limiter plugin ID should still be present")
}
