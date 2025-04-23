package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestUpdateGateway(t *testing.T) {
	t.Run("it should update a gateway's name", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Original Gateway Name",
			"subdomain": fmt.Sprintf("update-test-%d", time.Now().UnixNano()),
		})

		// Update the gateway's name
		updatePayload := map[string]interface{}{
			"name": "Updated Gateway Name",
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the gateway was updated by fetching it
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.Equal(t, "Updated Gateway Name", getResponse["name"])
	})

	t.Run("it should update a gateway's status", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Status Test Gateway",
			"subdomain": fmt.Sprintf("status-test-%d", time.Now().UnixNano()),
		})

		// Update the gateway's status
		updatePayload := map[string]interface{}{
			"status": "disabled",
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the gateway was updated by fetching it
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.Equal(t, "disabled", getResponse["status"])
	})

	t.Run("it should update a gateway's security configuration", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Security Config Test Gateway",
			"subdomain": fmt.Sprintf("security-test-%d", time.Now().UnixNano()),
		})

		// Update the gateway's security configuration
		updatePayload := map[string]interface{}{
			"security_config": map[string]interface{}{
				"allowed_hosts":              []string{"updated.example.com"},
				"allowed_hosts_are_regex":    true,
				"ssl_redirect":               true,
				"ssl_host":                   "secure.updated.example.com",
				"sts_seconds":                600,
				"sts_include_subdomains":     true,
				"frame_deny":                 true,
				"content_type_nosniff":       true,
				"browser_xss_filter":         true,
				"content_security_policy":    "default-src 'self' updated.example.com",
				"referrer_policy":            "strict-origin",
				"custom_frame_options_value": "DENY",
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the gateway was updated by fetching it
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.NotNil(t, getResponse["security_config"])

		securityConfig, ok := getResponse["security_config"].(map[string]interface{})
		assert.True(t, ok)
		assert.Contains(t, securityConfig["allowed_hosts"], "updated.example.com")
	})

	t.Run("it should update a gateway's telemetry configuration", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Telemetry Test Gateway",
			"subdomain": fmt.Sprintf("telemetry-test-%d", time.Now().UnixNano()),
		})

		// Update the gateway's telemetry configuration
		updatePayload := map[string]interface{}{
			"telemetry": map[string]interface{}{
				"enable_plugin_traces":  true,
				"enable_request_traces": true,
				"exporters": []map[string]interface{}{
					{
						"name": "kafka",
						"settings": map[string]interface{}{
							"brokers": []string{"localhost:9092"},
							"topic":   "telemetry",
							"host":    "localhost",
							"port":    "9092",
						},
					},
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the gateway was updated by fetching it
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.NotNil(t, getResponse["telemetry"])
	})

	t.Run("it should update a gateway's required plugins", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Plugins Test Gateway",
			"subdomain": fmt.Sprintf("plugins-test-%d", time.Now().UnixNano()),
		})

		// Update the gateway's required plugins
		updatePayload := map[string]interface{}{
			"required_plugins": map[string]interface{}{
				"rate_limiter": map[string]interface{}{
					"name":     "rate_limiter",
					"enabled":  true,
					"priority": 1,
					"stage":    "pre_request",
					"parallel": false,
					"settings": map[string]interface{}{
						"limits": map[string]interface{}{
							"per_ip": map[string]interface{}{
								"limit":  200,
								"window": "60s",
							},
						},
						"actions": map[string]interface{}{
							"type": "reject",
						},
						"redis_key_prefix": "updated_rate_limit",
					},
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify the gateway was updated by fetching it
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.NotNil(t, getResponse["required_plugins"])
	})

	t.Run("it should fail with invalid gateway ID", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"name": "Invalid Gateway Update",
		}

		invalidGatewayID := "invalid-uuid"
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, invalidGatewayID), updatePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail with non-existent gateway ID", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"name": "Non-existent Gateway Update",
		}

		nonExistentGatewayID := uuid.New().String()
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, nonExistentGatewayID), updatePayload)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("it should fail with invalid telemetry configuration", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Invalid Telemetry Gateway",
			"subdomain": fmt.Sprintf("invalid-telemetry-%d", time.Now().UnixNano()),
		})

		// Update with invalid telemetry configuration
		updatePayload := map[string]interface{}{
			"telemetry": map[string]interface{}{
				"enable_plugin_traces":  true,
				"enable_request_traces": true,
				"exporters": []map[string]interface{}{
					{
						"name": "invalid_exporter",
						"settings": map[string]interface{}{
							"invalid_setting": "value",
						},
					},
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), updatePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
