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

	// Delete CORS plugin via delete handler
	payload := map[string]interface{}{
		"type":    "gateway",
		"id":      gatewayID,
		"plugins": []string{"cors"},
	}
	status, _ := sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNoContent, status)

	// Verify CORS removed and rate_limiter remains
	status, response := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)
	rp, ok := response["required_plugins"].([]interface{})
	assert.True(t, ok)

	// ensure only rate_limiter remains
	names := make([]string, 0, len(rp))
	for _, p := range rp {
		if m, ok := p.(map[string]interface{}); ok {
			names = append(names, fmt.Sprintf("%v", m["name"]))
		}
	}
	assert.NotContains(t, names, "cors")
	assert.Contains(t, names, "rate_limiter")
}
