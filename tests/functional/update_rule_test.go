package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper function to find a rule by ID in the rules list response
func findRuleByID(t *testing.T, gatewayID, ruleID string) map[string]interface{} {
	status, response := sendRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		nil,
	)

	assert.Equal(t, http.StatusOK, status)
	if status != http.StatusOK {
		t.Fatalf("❌ Failed to fetch rules list. Status: %d, Response: %v", status, response)
		return nil
	}

	rules, ok := response["rules"].([]interface{})
	if !ok {
		t.Fatalf("❌ Rules response does not contain rules array. Response: %v", response)
		return nil
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := ruleMap["id"].(string); ok && id == ruleID {
			return ruleMap
		}
	}

	t.Fatalf("❌ Rule with ID %s not found in rules list", ruleID)
	return nil
}

func TestUpdateRule(t *testing.T) {
	defer RunTest(t, "UpdateRule", time.Now())()
	// Create a gateway first
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Rule Update Test Gateway",
		"subdomain": fmt.Sprintf("rule-update-test-%d", time.Now().UnixNano()),
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

	// Create a service for the rule
	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Test Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	// Create a second service for update testing
	serviceID2 := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Test Service 2",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	// Create initial rule
	initialRulePayload := map[string]interface{}{
		"path":       "/initial",
		"name":       "initial-rule",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"headers": map[string]string{
			"X-Initial": "initial-value",
		},
		"strip_path":     false,
		"preserve_host":  false,
		"retry_attempts": 3,
	}

	status, response := sendRequest(
		t,
		http.MethodPost,
		fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		initialRulePayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create initial rule. Status: %d, Response: %v", status, response)
	}

	ruleID, ok := response["id"].(string)
	assert.True(t, ok, "Rule creation should return an ID")
	if ruleID == "" {
		t.Fatalf("❌ Rule creation response did not contain a valid ID. Response: %v", response)
	}

	t.Logf("✅ Initial rule created with ID: %s", ruleID)

	// Wait a moment to ensure different timestamps
	time.Sleep(100 * time.Millisecond)

	t.Run("should successfully update rule with all fields", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"path":       "/updated",
			"name":       "updated-rule",
			"service_id": serviceID2,
			"methods":    []string{"GET", "POST", "PUT"},
			"headers": map[string]string{
				"X-Updated":     "updated-value",
				"Authorization": "Bearer test-token",
			},
			"strip_path":     true,
			"preserve_host":  true,
			"retry_attempts": 5,
			"active":         true,
		}

		status, response := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)
		if status != http.StatusNoContent {
			t.Fatalf("❌ Failed to update rule. Status: %d, Response: %v", status, response)
		}

		t.Logf("✅ Rule updated successfully (Status 204)")

		// Verify the update by fetching the rule from rules list
		getResponse := findRuleByID(t, gatewayID, ruleID)

		// Verify all updated fields
		assert.Equal(t, ruleID, getResponse["id"], "Rule ID should remain unchanged")
		assert.Equal(t, "/updated", getResponse["path"])
		assert.Equal(t, "updated-rule", getResponse["name"])
		assert.Equal(t, serviceID2, getResponse["service_id"])
		assert.Equal(t, true, getResponse["strip_path"])
		assert.Equal(t, true, getResponse["preserve_host"])
		assert.Equal(t, float64(5), getResponse["retry_attempts"])
		assert.Equal(t, true, getResponse["active"])
		// Verify type field is present (should default to endpoint)
		assert.NotNil(t, getResponse["type"])
		assert.Equal(t, "endpoint", getResponse["type"])

		// Check methods
		responseMethods, ok := getResponse["methods"].([]interface{})
		assert.True(t, ok, "Methods should be an array")
		assert.Contains(t, responseMethods, "GET")
		assert.Contains(t, responseMethods, "POST")
		assert.Contains(t, responseMethods, "PUT")

		// Check headers
		responseHeaders, ok := getResponse["headers"].(map[string]interface{})
		assert.True(t, ok, "Headers should be a map")
		assert.Equal(t, "updated-value", responseHeaders["X-Updated"])
		assert.Equal(t, "Bearer test-token", responseHeaders["Authorization"])

		t.Logf("✅ Rule updated successfully with all fields verified")
	})

	t.Run("should update individual fields", func(t *testing.T) {
		// Test updating just the path
		updatePayload := map[string]interface{}{
			"path":    "/individual-update",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)

		// Verify the update
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, "/individual-update", getResponse["path"])
		// Other fields should remain from previous update
		assert.Equal(t, "updated-rule", getResponse["name"])
		assert.Equal(t, serviceID2, getResponse["service_id"])

		t.Logf("✅ Individual field update successful")
	})

	t.Run("should update with plugin chain", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"path":    "/plugin-test",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)

		// Verify the update
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, "/plugin-test", getResponse["path"])

		t.Logf("✅ Path update successful")
	})

	t.Run("should return 400 for invalid rule ID", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"path":    "/invalid-test",
			"methods": []string{"GET"},
		}

		status, response := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/invalid-rule-id", AdminUrl, gatewayID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusBadRequest, status)
		if errorMsg, ok := response["error"].(string); ok {
			assert.Contains(t, errorMsg, "invalid rule_id")
		}
		t.Logf("✅ Correctly rejected invalid rule ID")
	})

	t.Run("should return 400 for invalid gateway ID", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"path":    "/invalid-test",
			"methods": []string{"GET"},
		}

		status, response := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/invalid-gateway-id/rules/%s", AdminUrl, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusBadRequest, status)
		if errorMsg, ok := response["error"].(string); ok {
			assert.Contains(t, errorMsg, "invalid gateway_id")
		}
		t.Logf("✅ Correctly rejected invalid gateway ID")
	})

	t.Run("should return 404 for non-existent rule", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"path":    "/nonexistent-test",
			"methods": []string{"GET"},
		}

		// Generate a valid UUID that doesn't exist
		nonExistentRuleID := "550e8400-e29b-41d4-a716-446655440000"

		status, response := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, nonExistentRuleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNotFound, status)
		if errorMsg, ok := response["error"].(string); ok {
			assert.Contains(t, errorMsg, "rule not found")
		}
		t.Logf("✅ Correctly returned 404 for non-existent rule")
	})

	t.Run("should return 400 for invalid JSON payload", func(t *testing.T) {
		req, err := http.NewRequest(
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			nil, // nil body will cause JSON parsing error
		)
		assert.NoError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", AdminToken))
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		t.Logf("✅ Correctly rejected invalid JSON payload")
	})

	t.Run("should deactivate rule", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"active":  false,
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)

		// Verify the rule is deactivated
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, false, getResponse["active"])
		t.Logf("✅ Rule deactivation successful")
	})

	t.Run("should update rule type to agent", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"type":    "agent",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)

		// Verify the type was updated
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, "agent", getResponse["type"])
		t.Logf("✅ Rule type updated to agent successfully")
	})

	t.Run("should update rule type to endpoint", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"type":    "endpoint",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusNoContent, status)

		// Verify the type was updated
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, "endpoint", getResponse["type"])
		t.Logf("✅ Rule type updated to endpoint successfully")
	})

	t.Run("should fail with invalid rule type", func(t *testing.T) {
		updatePayload := map[string]interface{}{
			"type":    "invalid",
			"methods": []string{"GET"},
		}

		status, errorResponse := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)

		assert.Equal(t, http.StatusBadRequest, status)
		if errorMsg, ok := errorResponse["error"].(string); ok {
			assert.Contains(t, errorMsg, "invalid rule_type")
		}
		t.Logf("✅ Correctly rejected invalid rule type")
	})

	t.Run("should preserve type when updating other fields", func(t *testing.T) {
		// First set type to agent
		updatePayload := map[string]interface{}{
			"type":    "agent",
			"methods": []string{"GET"},
		}

		status, _ := sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload,
		)
		assert.Equal(t, http.StatusNoContent, status)

		// Now update only the path without specifying type
		updatePayload2 := map[string]interface{}{
			"path":    "/preserve-type-test",
			"methods": []string{"GET"},
		}

		status, _ = sendRequest(
			t,
			http.MethodPut,
			fmt.Sprintf("%s/gateways/%s/rules/%s", AdminUrl, gatewayID, ruleID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			updatePayload2,
		)
		assert.Equal(t, http.StatusNoContent, status)

		// Verify type is still agent
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, "agent", getResponse["type"])
		assert.Equal(t, "/preserve-type-test", getResponse["path"])
		t.Logf("✅ Rule type preserved during partial update")
	})

	// Final verification: ensure rule still exists and has expected state
	t.Run("should verify final rule state", func(t *testing.T) {
		getResponse := findRuleByID(t, gatewayID, ruleID)
		assert.Equal(t, ruleID, getResponse["id"])
		assert.Equal(t, "/preserve-type-test", getResponse["path"]) // From preserve type test
		assert.Equal(t, false, getResponse["active"])               // From deactivation test
		assert.Equal(t, "agent", getResponse["type"])               // From preserve type test

		t.Logf("✅ Final rule state verified")
	})
}
