package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeleteGateway(t *testing.T) {
	defer RunTest(t, "DeleteGateway", time.Now())()
	t.Run("it should delete a gateway and verify it no longer exists", func(t *testing.T) {
		// Create a gateway first
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Gateway to Delete",
			"subdomain": fmt.Sprintf("delete-test-%d", time.Now().UnixNano()),
		})

		// Verify the gateway exists before deletion
		getStatus, getResponse := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusOK, getStatus)
		assert.NotEmpty(t, getResponse["id"])
		assert.Equal(t, gatewayID, getResponse["id"])

		// Delete the gateway
		deleteStatus, _ := sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusNoContent, deleteStatus)

		// Verify the gateway no longer exists
		getStatusAfterDelete, _ := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusNotFound, getStatusAfterDelete, "Gateway should not exist after deletion")
	})

	t.Run("it should fail to delete a non-existent gateway", func(t *testing.T) {
		nonExistentGatewayID := "00000000-0000-0000-0000-000000000000"

		// Try to delete a non-existent gateway
		deleteStatus, _ := sendRequest(t, http.MethodDelete, fmt.Sprintf("%s/gateways/%s", AdminUrl, nonExistentGatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, nil)
		assert.Equal(t, http.StatusNotFound, deleteStatus, "Should return 404 for non-existent gateway")
	})
}

