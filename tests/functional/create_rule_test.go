package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateRule(t *testing.T) {
	// Create a gateway first to use in the rule tests
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Rule Test Gateway",
		"subdomain": fmt.Sprintf("rule-test-%d", time.Now().UnixNano()),
	})

	// Create an upstream for the service
	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Test Upstream",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "example.com",
				"port":     80,
				"protocol": "http",
				"weight":   1,
			},
		},
	})

	// Create a service to use in the rule tests
	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Test Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	t.Run("it should create a rule with minimal configuration", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "/test", response["path"])
		assert.Equal(t, serviceID, response["service_id"])
		assert.Equal(t, []interface{}{"GET"}, response["methods"])
		assert.Equal(t, gatewayID, response["gateway_id"])
	})

	t.Run("it should create a rule with headers", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-headers",
			"name":       "rulename",
			"service_id": serviceID,
			"methods":    []string{"GET", "POST"},
			"headers": map[string]interface{}{
				"Content-Type": "application/json",
				"X-API-Key":    "test-key",
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "/test-headers", response["path"])
		assert.Equal(t, serviceID, response["service_id"])
		assert.Equal(t, []interface{}{"GET", "POST"}, response["methods"])
		assert.NotNil(t, response["headers"])
	})

	t.Run("it should create a rule with strip_path and preserve_host", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":          "/test-options",
			"name":          "rulename",
			"service_id":    serviceID,
			"methods":       []string{"GET"},
			"strip_path":    true,
			"preserve_host": true,
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "/test-options", response["path"])
		assert.Equal(t, serviceID, response["service_id"])
		assert.Equal(t, true, response["strip_path"])
		assert.Equal(t, true, response["preserve_host"])
	})

	t.Run("it should create a rule with retry_attempts", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":           "/test-retry",
			"name":           "rulename",
			"service_id":     serviceID,
			"methods":        []string{"GET"},
			"retry_attempts": 3,
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "/test-retry", response["path"])
		assert.Equal(t, serviceID, response["service_id"])
		assert.Equal(t, float64(3), response["retry_attempts"])
	})

	t.Run("it should create a rule with plugin chain", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-plugins",
			"name":       "rulename",
			"service_id": serviceID,
			"methods":    []string{"GET"},
			"plugin_chain": []map[string]interface{}{
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

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "/test-plugins", response["path"])
		assert.Equal(t, serviceID, response["service_id"])
		assert.NotNil(t, response["plugin_chain"])
	})

	t.Run("it should fail when path is missing", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"service_id": serviceID,
			"name":       "rulename",
			"methods":    []string{"GET"},
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail when service_id is missing", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":    "/test-missing-service",
			"name":    "rulename",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail when methods are missing", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-missing-methods",
			"service_id": serviceID,
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail with non-existent gateway ID", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-nonexistent-gateway",
			"name":       "rulename",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		}

		nonExistentGatewayID := uuid.New().String()
		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, nonExistentGatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)
	})

	t.Run("it should fail with non-existent service ID", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-nonexistent-service",
			"name":       "rulename",
			"service_id": uuid.New().String(),
			"methods":    []string{"GET"},
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusCreated, status)
	})

	t.Run("it should fail with invalid HTTP method", func(t *testing.T) {
		rulePayload := map[string]interface{}{
			"path":       "/test-invalid-method",
			"name":       "rulename",
			"service_id": serviceID,
			"methods":    []string{"INVALID"},
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
