package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateUpstream(t *testing.T) {
	// Create a gateway first to use in the upstream tests
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Upstream Test Gateway",
		"subdomain": fmt.Sprintf("upstream-test-%d", time.Now().UnixNano()),
	})

	t.Run("it should create an upstream with minimal configuration", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Minimal Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Minimal Upstream", response["name"])
		assert.Equal(t, "round-robin", response["algorithm"])
		assert.NotNil(t, response["targets"])
	})

	t.Run("it should create an upstream with multiple targets", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Multi-Target Upstream",
			"algorithm": "least-conn",
			"targets": []map[string]interface{}{
				{
					"host":     "api1.example.com",
					"port":     443,
					"protocol": "https",
					"weight":   2,
					"priority": 1,
				},
				{
					"host":     "api2.example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
					"priority": 2,
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Multi-Target Upstream", response["name"])
		assert.Equal(t, "least-conn", response["algorithm"])

		targets, ok := response["targets"].([]interface{})
		assert.True(t, ok)
		assert.Equal(t, 2, len(targets))
	})

	t.Run("it should create an upstream with health checks", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Health Check Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "health.example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
			"health_checks": map[string]interface{}{
				"passive":   true,
				"path":      "/health",
				"threshold": 3,
				"interval":  10,
				"headers": map[string]interface{}{
					"Content-Type": "application/json",
				},
			},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Health Check Upstream", response["name"])
		assert.NotNil(t, response["health_checks"])
	})

	t.Run("it should create an upstream with tags", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Tagged Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "tagged.example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
			"tags": []string{"production", "api", "external"},
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Tagged Upstream", response["name"])

		tags, ok := response["tags"].([]interface{})
		assert.True(t, ok)
		assert.Equal(t, 3, len(tags))
	})

	t.Run("it should fail when name is missing", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("it should fail when targets are missing", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Missing Targets Upstream",
			"algorithm": "round-robin",
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("it should fail with invalid gateway ID", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Invalid Gateway Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
		}

		invalidGatewayID := "invalid-uuid"
		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, invalidGatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail with non-existent gateway ID", func(t *testing.T) {
		upstreamPayload := map[string]interface{}{
			"name":      "Non-existent Gateway Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "example.com",
					"port":     443,
					"protocol": "https",
					"weight":   1,
				},
			},
		}

		nonExistentGatewayID := uuid.New().String()
		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, nonExistentGatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, upstreamPayload)
		assert.Equal(t, http.StatusCreated, status)
	})
}
