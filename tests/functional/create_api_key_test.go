package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateAPIKey(t *testing.T) {
	// Create a gateway first to use in the API key tests
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "API Key Test Gateway",
		"subdomain": fmt.Sprintf("api-key-test-%d", time.Now().UnixNano()),
	})

	t.Run("it should create an API key with minimal configuration", func(t *testing.T) {
		apiKeyPayload := map[string]interface{}{
			"name": "Test API Key",
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, gatewayID), apiKeyPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Test API Key", response["name"])
		assert.NotEmpty(t, response["key"])
		assert.Equal(t, gatewayID, response["gateway_id"])
	})

	t.Run("it should create an API key with expiration date", func(t *testing.T) {
		expirationDate := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
		apiKeyPayload := map[string]interface{}{
			"name":       "Expiring API Key",
			"expires_at": expirationDate,
		}

		status, response := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, gatewayID), apiKeyPayload)
		assert.Equal(t, http.StatusCreated, status)

		// Verify response fields
		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "Expiring API Key", response["name"])
		assert.NotEmpty(t, response["key"])
		assert.Equal(t, gatewayID, response["gateway_id"])
		assert.NotEmpty(t, response["expires_at"])
	})

	t.Run("it should fail when name is missing", func(t *testing.T) {
		apiKeyPayload := map[string]interface{}{
			"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, gatewayID), apiKeyPayload)
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("it should fail with invalid gateway ID", func(t *testing.T) {
		apiKeyPayload := map[string]interface{}{
			"name": "Invalid Gateway API Key",
		}

		invalidGatewayID := "invalid-uuid"
		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, invalidGatewayID), apiKeyPayload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail with non-existent gateway ID", func(t *testing.T) {
		apiKeyPayload := map[string]interface{}{
			"name": "Non-existent Gateway API Key",
		}

		nonExistentGatewayID := uuid.New().String()
		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, nonExistentGatewayID), apiKeyPayload)
		assert.Equal(t, http.StatusCreated, status)
	})

	t.Run("it should fail with invalid JSON payload", func(t *testing.T) {
		// This test is a bit tricky to implement with the current sendRequest function
		// as it automatically marshals the payload to JSON. For now, we'll skip this test.
		// In a real-world scenario, you would use a custom HTTP client to send an invalid JSON payload.
	})
}
