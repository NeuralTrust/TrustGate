package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdatePlugins(t *testing.T) {
	// Create a gateway to work with
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Update Plugins Gateway",
		"subdomain": fmt.Sprintf("update-plugins-%d", time.Now().UnixNano()),
	})

	t.Run("should add plugins to gateway using new updates format", func(t *testing.T) {
		payload := map[string]interface{}{
			"type": "gateway",
			"id":   gatewayID,
			"updates": []map[string]interface{}{
				{
					"operation": "add",
					"plugin": map[string]interface{}{
						"name":     "rate_limiter",
						"enabled":  true,
						"stage":    "pre_request",
						"priority": 1,
						"parallel": false,
						"settings": map[string]interface{}{
							"limits": map[string]interface{}{
								"per_ip": map[string]interface{}{
									"limit":  10,
									"window": "30s",
								},
							},
							"actions": map[string]interface{}{
								"type": "reject",
							},
						},
					},
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify via GET gateway
		status, response := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusOK, status)
		rp, ok := response["required_plugins"].([]interface{})
		assert.True(t, ok)
		assert.GreaterOrEqual(t, len(rp), 1)
		first, ok := rp[0].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "rate_limiter", first["name"])
		assert.Equal(t, "pre_request", first["stage"])
	})

	t.Run("should update rule plugin chain using new updates format", func(t *testing.T) {
		// Create upstream, service, and rule
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Update Plugins Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{"host": "example.com", "port": 80, "protocol": "http", "weight": 1},
			},
		})
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Update Plugins Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		// Create a rule and capture its ID
		rulePayload := map[string]interface{}{
			"path":       "/update-plugins",
			"name":       "rule-update-plugins",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		}
		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)
		ruleID, ok := response["id"].(string)
		assert.True(t, ok)

		// Add plugins to the rule using the new updates format
		payload := map[string]interface{}{
			"type": "rule",
			"id":   ruleID,
			"updates": []map[string]interface{}{
				{
					"operation": "add",
					"plugin": map[string]interface{}{
						"name":     "rate_limiter",
						"enabled":  true,
						"stage":    "pre_request",
						"priority": 2,
						"parallel": false,
						"settings": map[string]interface{}{
							"limits": map[string]interface{}{
								"per_user": map[string]interface{}{
									"limit":  5,
									"window": "15s",
								},
							},
							"actions": map[string]interface{}{
								"type": "reject",
							},
						},
					},
				},
			},
		}

		status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify by listing rules (note: rules are cached, so changes may take effect on next request)
		status, response = sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusOK, status)
		rules, ok := response["rules"].([]interface{})
		assert.True(t, ok)
		assert.Greater(t, len(rules), 0)
		// Find our rule
		var ourRule map[string]interface{}
		for _, r := range rules {
			rule, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if rule["id"] == ruleID {
				ourRule = rule
				break
			}
		}
		assert.NotNil(t, ourRule)

		// Check plugin chain
		pc, ok := ourRule["plugin_chain"].([]interface{})
		assert.True(t, ok)
		assert.Equal(t, 1, len(pc))
		firstPlugin, ok := pc[0].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "rate_limiter", firstPlugin["name"])
		assert.Equal(t, "pre_request", firstPlugin["stage"])
	})

	t.Run("should perform multiple operations on gateway plugins", func(t *testing.T) {
		// First, add a plugin
		addPayload := map[string]interface{}{
			"type": "gateway",
			"id":   gatewayID,
			"updates": []map[string]interface{}{
				{
					"operation": "add",
					"plugin": map[string]interface{}{
						"name":     "cors",
						"enabled":  true,
						"stage":    "pre_request",
						"priority": 0,
						"settings": map[string]interface{}{
							"allowed_origins": []string{"*"},
						},
					},
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, addPayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Now perform multiple operations: edit rate_limiter and delete cors
		multiPayload := map[string]interface{}{
			"type": "gateway",
			"id":   gatewayID,
			"updates": []map[string]interface{}{
				{
					"operation": "edit",
					"plugin": map[string]interface{}{
						"name":     "rate_limiter",
						"enabled":  false, // Disable it
						"stage":    "pre_request",
						"priority": 1,
						"settings": map[string]interface{}{
							"limits": map[string]interface{}{
								"per_ip": map[string]interface{}{
									"limit":  100, // Change limit
									"window": "60s",
								},
							},
							"actions": map[string]interface{}{
								"type": "reject",
							},
						},
					},
				},
				{
					"operation":   "delete",
					"plugin_name": "cors",
				},
			},
		}

		status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, multiPayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the changes
		status, response := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusOK, status)
		rp, ok := response["required_plugins"].([]interface{})
		assert.True(t, ok)
		assert.Equal(t, 1, len(rp)) // Should only have rate_limiter now (cors deleted)

		first, ok := rp[0].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "rate_limiter", first["name"])
		assert.Equal(t, false, first["enabled"]) // Should be disabled now
	})
}
