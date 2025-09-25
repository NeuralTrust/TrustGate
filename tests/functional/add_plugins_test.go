package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAddPluginsHandler_GatewaySuccess(t *testing.T) {
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Add Plugins Gateway",
		"subdomain": fmt.Sprintf("add-plugins-%d", time.Now().UnixNano()),
	})

	payload := map[string]interface{}{
		"type": "gateway",
		"id":   gatewayID,
		"plugins": []map[string]interface{}{
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
	}

	status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNoContent, status)

	// Verify plugin was added and has an ID
	status, getResp := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)

	requiredPlugins, ok := getResp["required_plugins"].([]interface{})
	assert.True(t, ok)
	assert.NotEmpty(t, requiredPlugins)

	var found bool
	for _, p := range requiredPlugins {
		if m, ok := p.(map[string]interface{}); ok {
			if m["name"] == "cors" && m["stage"] == "pre_request" {
				found = true
				if id, ok := m["id"].(string); ok {
					assert.NotEmpty(t, id)
				}
			}
		}
	}
	assert.True(t, found, "added plugin not found in gateway")
}

func TestAddPluginsHandler_GatewayDuplicateStage(t *testing.T) {
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Add Plugins Duplicate",
		"subdomain": fmt.Sprintf("add-plugins-dup-%d", time.Now().UnixNano()),
		"required_plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"allowed_origins": []string{"*"},
					"allowed_methods": []string{"GET"},
					"allowed_headers": []string{"Content-Type"},
					"max_age":         "300s",
				},
			},
		},
	})

	payload := map[string]interface{}{
		"type": "gateway",
		"id":   gatewayID,
		"plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 2,
				"parallel": false,
			},
		},
	}

	status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusBadRequest, status)
	if msg, ok := resp["error"].(string); ok {
		assert.Contains(t, msg, "already exists for stage")
	}
}

func TestAddPluginsHandler_RuleSuccess(t *testing.T) {
	// Create gateway
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Add Plugins Rule",
		"subdomain": fmt.Sprintf("add-plugins-rule-%d", time.Now().UnixNano()),
	})
	// Create upstream
	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Upstream For Rule",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{"host": "example.com", "port": 80, "protocol": "http", "weight": 1},
		},
	})
	// Create service
	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Service For Rule",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})
	// Create rule minimal
	rulePayload := map[string]interface{}{
		"path":       "/add-plugin-rule",
		"name":       "rulename",
		"service_id": serviceID,
		"methods":    []string{"GET"},
	}
	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	// Add plugin to rule
	payload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"allowed_origins": []string{"*"},
					"allowed_methods": []string{"GET"},
					"allowed_headers": []string{"Content-Type"},
					"max_age":         "120s",
				},
			},
		},
	}
	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusNoContent, status)

	// Verify rule has plugin
	status, listResp := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)

	rules, ok := listResp["rules"].([]interface{})
	assert.True(t, ok)

	var found bool
	for _, it := range rules {
		m, ok := it.(map[string]interface{})
		assert.True(t, ok)
		idStr, ok := m["id"].(string)
		assert.True(t, ok)
		if idStr == ruleID {
			if chain, ok := m["plugin_chain"].([]interface{}); ok {
				for _, p := range chain {
					pm, ok := p.(map[string]interface{})
					assert.True(t, ok)
					if pm["name"] == "cors" && pm["stage"] == "pre_request" {
						found = true
						break
					}
				}
			}
		}
	}
	assert.True(t, found, "added plugin not found in rule plugin_chain")
}

func TestAddPluginsHandler_ValidationErrors(t *testing.T) {
	// Invalid type
	payload := map[string]interface{}{
		"type": "invalid",
		"id":   "some-id",
		"plugins": []map[string]interface{}{
			{"name": "cors", "stage": "pre_request"},
		},
	}
	status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusBadRequest, status)
	if msg, ok := resp["error"].(string); ok {
		assert.Contains(t, msg, "type must be")
	}

	// Missing id
	payload = map[string]interface{}{
		"type": "gateway",
		"plugins": []map[string]interface{}{
			{"name": "cors", "stage": "pre_request"},
		},
	}
	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusBadRequest, status)

	// Missing plugins
	payload = map[string]interface{}{
		"type": "gateway",
		"id":   "some-id",
	}
	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusBadRequest, status)

	// Invalid UUID for rule id
	payload = map[string]interface{}{
		"type": "rule",
		"id":   "not-a-uuid",
		"plugins": []map[string]interface{}{
			{"name": "cors", "stage": "pre_request"},
		},
	}
	status, resp = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, payload)
	assert.Equal(t, http.StatusBadRequest, status)
	if msg, ok := resp["error"].(string); ok {
		assert.Contains(t, msg, "invalid rule ID")
	}
}
