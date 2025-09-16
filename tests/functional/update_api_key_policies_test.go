package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUpdateAPIKeyPolicies(t *testing.T) {
	// Create a gateway
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Update Policies Gateway",
		"subdomain": fmt.Sprintf("update-policies-%d", time.Now().UnixNano()),
	})

	// Create an upstream
	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Policies Upstream",
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

	// Create a service
	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Policies Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	// Create a rule and capture its ID
	rulePayload := map[string]interface{}{
		"path":       "/policies-test",
		"name":       "policies-rule",
		"service_id": serviceID,
		"methods":    []string{"GET"},
	}
	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok, "rule ID should be a string")
	assert.NotEmpty(t, ruleID)

	// Create an API key and obtain its ID via list endpoint
	createdKey := CreateApiKey(t, gatewayID)
	status, listResp := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/gateways/%s/keys", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, nil)
	assert.Equal(t, http.StatusOK, status)
	var apiKeyID string
	if keys, ok := listResp["api_keys"].([]interface{}); ok {
		for _, k := range keys {
			if m, ok := k.(map[string]interface{}); ok {
				if m["key"] == createdKey {
					apiKeyID, ok = m["id"].(string)
					if !ok {
						t.Fatalf("API key ID should be a string")
					}
					break
				}
			}
		}
	}
	assert.NotEmpty(t, apiKeyID)

	t.Run("it should set policies successfully", func(t *testing.T) {
		payload := map[string]interface{}{
			"policies": []string{ruleID},
		}
		status, resp := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s/keys/%s/policies", AdminUrl, gatewayID, apiKeyID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusOK, status)
		// Verify response contains the policy
		if policies, ok := resp["policies"].([]interface{}); ok {
			found := false
			for _, p := range policies {
				if ps, ok := p.(string); ok && ps == ruleID {
					found = true
					break
				}
			}
			assert.True(t, found, "expected rule id in policies")
		} else {
			t.Fatalf("invalid response policies: %v", resp["policies"])
		}
	})

	t.Run("it should clear policies when empty array provided", func(t *testing.T) {
		payload := map[string]interface{}{
			"policies": []string{},
		}
		status, resp := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s/keys/%s/policies", AdminUrl, gatewayID, apiKeyID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusOK, status)
		if policies, ok := resp["policies"].([]interface{}); ok {
			assert.Equal(t, 0, len(policies))
		} else {
			// Some encoders may omit empty arrays; accept nil as empty
			assert.Nil(t, resp["policies"])
		}
	})

	t.Run("it should fail with invalid policy id format", func(t *testing.T) {
		payload := map[string]interface{}{
			"policies": []string{"not-a-uuid"},
		}
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s/keys/%s/policies", AdminUrl, gatewayID, apiKeyID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should fail when policy rule belongs to a different gateway", func(t *testing.T) {
		// Prepare another gateway and rule
		otherGatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Other Gateway",
			"subdomain": fmt.Sprintf("other-gw-%d", time.Now().UnixNano()),
		})
		otherUpstreamID := CreateUpstream(t, otherGatewayID, map[string]interface{}{
			"name":      "Other Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{{
				"host":     "example.com",
				"port":     80,
				"protocol": "http",
				"weight":   1,
			}},
		})
		otherServiceID := CreateService(t, otherGatewayID, map[string]interface{}{
			"name":        "Other Service",
			"type":        "upstream",
			"upstream_id": otherUpstreamID,
		})
		otherRulePayload := map[string]interface{}{
			"path":       "/other-rule",
			"name":       "other-rule-name",
			"service_id": otherServiceID,
			"methods":    []string{"GET"},
		}
		status, otherRuleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, otherGatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, otherRulePayload)
		assert.Equal(t, http.StatusCreated, status)
		otherRuleID, ok := otherRuleResp["id"].(string)
		assert.True(t, ok, "other rule ID should be a string")
		assert.NotEmpty(t, otherRuleID)

		// Try to set a policy from another gateway -> should fail 400
		payload := map[string]interface{}{
			"policies": []string{otherRuleID},
		}
		status, _ = sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s/keys/%s/policies", AdminUrl, gatewayID, apiKeyID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("it should return 404 when api key does not exist", func(t *testing.T) {
		payload := map[string]interface{}{
			"policies": []string{ruleID},
		}
		nonExistentKeyID := "00000000-0000-0000-0000-000000000001"
		status, _ := sendRequest(t, http.MethodPut, fmt.Sprintf("%s/gateways/%s/keys/%s/policies", AdminUrl, gatewayID, nonExistentKeyID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusNotFound, status)
	})
}
