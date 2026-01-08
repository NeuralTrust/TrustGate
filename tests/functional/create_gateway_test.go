package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateGateway(t *testing.T) {
	t.Run("it should create a gateway with minimal configuration", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{
			"name": "Minimal Gateway",
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Minimal Gateway", response["name"])
	})

	t.Run("it should fail when name is missing", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("it should create a gateway with security configuration", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{
			"name": "Security Config Gateway",
			"security_config": map[string]interface{}{
				"allowed_hosts":              []string{"example.com"},
				"allowed_hosts_are_regex":    false,
				"ssl_redirect":               true,
				"ssl_host":                   "secure.example.com",
				"sts_seconds":                300,
				"sts_include_subdomains":     true,
				"frame_deny":                 true,
				"content_type_nosniff":       true,
				"browser_xss_filter":         true,
				"content_security_policy":    "default-src 'self'",
				"referrer_policy":            "no-referrer",
				"custom_frame_options_value": "SAMEORIGIN",
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Security Config Gateway", response["name"])
		assert.NotNil(t, response["security_config"])
	})

	t.Run("it should create a gateway with telemetry configuration", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{
			"name": "Telemetry Gateway",
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

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Telemetry Gateway", response["name"])
		assert.NotNil(t, response["telemetry"])
	})

	t.Run("it should create a gateway with TLS configuration", func(t *testing.T) {
		// Generate valid certificate bundle for testing
		bundle := generateCertBundle(t, "localhost")

		gatewayPayload := map[string]interface{}{
			"name": "TLS Gateway",
			"client_tls": map[string]interface{}{
				"localhost": map[string]interface{}{
					"allow_insecure_connections": false,
					"disable_system_ca_pool":     false,
					"min_version":                "TLS12",
					"max_version":                "TLS13",
					"ca_cert":                    bundle.CACertPEM,
					"client_certs": map[string]interface{}{
						"certificate": bundle.ClientCertPEM,
						"private_key": bundle.ClientKeyPEM,
					},
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "TLS Gateway", response["name"])
		assert.NotNil(t, response["client_tls"])
	})

	t.Run("it should create a gateway with required plugins", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{
			"name": "Required Plugins Gateway",
			"required_plugins": []map[string]interface{}{
				{
					"name":     "rate_limiter",
					"enabled":  true,
					"priority": 1,
					"stage":    "pre_request",
					"parallel": false,
					"settings": map[string]interface{}{
						"limits": map[string]interface{}{
							"per_ip": map[string]interface{}{
								"limit":  100,
								"window": "60s",
							},
						},
						"actions": map[string]interface{}{
							"type": "reject",
						},
						"redis_key_prefix": "rate_limit",
					},
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Required Plugins Gateway", response["name"])
		assert.NotNil(t, response["required_plugins"])
	})

	t.Run("it should fail when telemetry exporters have duplicate provider names", func(t *testing.T) {
		gatewayPayload := map[string]interface{}{
			"name": "Duplicate Telemetry Providers",
			"telemetry": map[string]interface{}{
				"exporters": []map[string]interface{}{
					{
						"name": "kafka",
						"settings": map[string]interface{}{
							"brokers": []string{"localhost:9092"},
							"topic":   "telemetry",
						},
					},
					{
						"name": "kafka",
						"settings": map[string]interface{}{
							"brokers": []string{"localhost:9092"},
							"topic":   "telemetry2",
						},
					},
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, gatewayPayload)
		assert.Equal(t, http.StatusBadRequest, status)
		if errMsg, ok := response["error"].(string); ok {
			assert.Contains(t, errMsg, "duplicate telemetry exporter provider")
		}
	})
}
