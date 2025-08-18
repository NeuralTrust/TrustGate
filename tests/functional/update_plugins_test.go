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

	t.Run("should update gateway required plugins", func(t *testing.T) {
		payload := map[string]interface{}{
			"type": "gateway",
			"id":   gatewayID,
			"plugin_chain": []map[string]interface{}{
				{
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

	t.Run("should update rule plugin chain", func(t *testing.T) {
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

		// Update plugins for the rule
		payload := map[string]interface{}{
			"type": "rule",
			"id":   ruleID,
			"plugin_chain": []map[string]interface{}{
				{
					"name":     "rate_limiter",
					"enabled":  true,
					"stage":    "pre_request",
					"priority": 2,
					"parallel": false,
					"settings": map[string]interface{}{
						"limits": map[string]interface{}{
							"per_ip": map[string]interface{}{
								"limit":  5,
								"window": "30s",
							},
						},
						"actions": map[string]interface{}{
							"type": "reject",
						},
					},
				},
			},
		}

		status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify via listing rules
		status, rulesResp := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusOK, status)

		rules, ok := rulesResp["rules"].([]interface{})
		assert.True(t, ok)

		var found bool
		for _, r := range rules {
			rm, ok := r.(map[string]interface{})
			assert.True(t, ok)
			if rm["id"] == ruleID {
				pc, ok := rm["plugin_chain"].([]interface{})
				assert.True(t, ok)
				assert.GreaterOrEqual(t, len(pc), 1)
				p0, ok := pc[0].(map[string]interface{})
				assert.True(t, ok)
				assert.Equal(t, "rate_limiter", p0["name"])
				assert.Equal(t, "pre_request", p0["stage"])
				found = true
				break
			}
		}
		assert.True(t, found, "rule not found in list after update")
	})

	t.Run("should fail with invalid type", func(t *testing.T) {
		payload := map[string]interface{}{
			"type": "invalid",
			"id":   gatewayID,
		}
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("should fail with invalid gateway ID format", func(t *testing.T) {
		payload := map[string]interface{}{
			"type": "gateway",
			"id":   "not-a-uuid",
		}
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("should return 404 for non-existent rule", func(t *testing.T) {
		payload := map[string]interface{}{
			"type": "rule",
			"id":   "00000000-0000-0000-0000-000000000000",
		}
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusNotFound, status)
	})
}
