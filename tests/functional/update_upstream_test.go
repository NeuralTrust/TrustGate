package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func waitForUpstreamTags(t *testing.T, gatewayID, upstreamID string, expected []string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, resp := sendRequest(t, http.MethodGet,
			fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
			map[string]string{"Authorization": fmt.Sprintf("Bearer %s", AdminToken)},
			nil,
		)
		if status == http.StatusOK {
			if tagsInterface, ok := resp["tags"]; ok {
				if tagsArray, ok := tagsInterface.([]interface{}); ok {
					var actualTags []string
					for _, tag := range tagsArray {
						if tagStr, ok := tag.(string); ok {
							actualTags = append(actualTags, tagStr)
						}
					}
					// Check if tags match (order doesn't matter)
					if len(expected) == len(actualTags) {
						matches := true
						for _, expectedTag := range expected {
							found := false
							for _, actualTag := range actualTags {
								if expectedTag == actualTag {
									found = true
									break
								}
							}
							if !found {
								matches = false
								break
							}
						}
						if matches {
							t.Logf("✅ Cache updated with expected tags: %v", actualTags)
							return
						}
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("❌ Timeout waiting for updated tags. Expected: %v", expected)
}

func TestUpdateUpstreamTags(t *testing.T) {
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-gateway-%d", time.Now().Unix()),
		"subdomain": fmt.Sprintf("gateway-%d", time.Now().Unix()),
	}
	gatewayID := CreateGateway(t, gatewayPayload)

	// Create an upstream with initial tags
	initialTags := []string{"initial", "test", "upstream"}
	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"tags":      initialTags,
		"targets": []map[string]interface{}{
			{
				"host":     "example.com",
				"port":     80,
				"protocol": "http",
				"weight":   100,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)
	t.Logf("✅ Upstream created with ID: %s and initial tags: %v", upstreamID, initialTags)

	// Update the upstream with new tags
	newTags := []string{"updated", "new", "tags", "test"}
	updatePayload := map[string]interface{}{
		"name":      fmt.Sprintf("updated-upstream-%d", time.Now().Unix()),
		"algorithm": "weighted-round-robin",
		"tags":      newTags,
		"targets": []map[string]interface{}{
			{
				"host":     "updated.example.com",
				"port":     443,
				"protocol": "https",
				"weight":   50,
			},
			{
				"host":     "backup.example.com",
				"port":     80,
				"protocol": "http",
				"weight":   30,
			},
		},
	}

	// Perform the update
	updateStatus, updateResponse := sendRequest(
		t,
		http.MethodPut,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		updatePayload,
	)

	assert.Equal(t, http.StatusOK, updateStatus)
	if updateStatus != http.StatusOK {
		t.Fatalf("❌ Failed to update upstream. Status: %d, Response: %v", updateStatus, updateResponse)
	}

	t.Logf("✅ Upstream updated. Response: %v", updateResponse)

	// Verify the response contains the updated data
	responseTagsInterface, exists := updateResponse["tags"]
	assert.True(t, exists, "Response should contain 'tags' field")
	
	if exists {
		responseTags, ok := responseTagsInterface.([]interface{})
		assert.True(t, ok, "Tags should be an array")
		
		if ok {
			// Convert []interface{} to []string for comparison
			var responseTagsStrings []string
			for _, tag := range responseTags {
				if tagStr, ok := tag.(string); ok {
					responseTagsStrings = append(responseTagsStrings, tagStr)
				}
			}
			
			assert.ElementsMatch(t, newTags, responseTagsStrings, "Response tags should match the updated tags")
			t.Logf("✅ Response tags verified: %v", responseTagsStrings)
		}
	}

	// Verify the name was updated
	responseName, exists := updateResponse["name"]
	assert.True(t, exists, "Response should contain 'name' field")
	if exists {
		assert.Equal(t, updatePayload["name"], responseName, "Response name should match the updated name")
	}

	// Verify the algorithm was updated
	responseAlgorithm, exists := updateResponse["algorithm"]
	assert.True(t, exists, "Response should contain 'algorithm' field")
	if exists {
		assert.Equal(t, updatePayload["algorithm"], responseAlgorithm, "Response algorithm should match the updated algorithm")
	}

	// Use polling to wait for the cache/data to be consistent
	waitForUpstreamTags(t, gatewayID, upstreamID, newTags, 10*time.Second)

	// Final verification: fetch the upstream from the database 
	getStatus, getResponse := sendRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		nil,
	)

	assert.Equal(t, http.StatusOK, getStatus)
	if getStatus != http.StatusOK {
		t.Fatalf("❌ Failed to fetch upstream. Status: %d, Response: %v", getStatus, getResponse)
	}

	// Final checks - by this time the waitForUpstreamTags should have ensured consistency
	assert.Equal(t, updateResponse["name"], getResponse["name"], "Update response name should match database")
	assert.Equal(t, updateResponse["algorithm"], getResponse["algorithm"], "Update response algorithm should match database")
	assert.Equal(t, updateResponse["id"], getResponse["id"], "Update response ID should match database")

	t.Logf("✅ Update upstream test completed successfully")
}

func TestUpdateUpstreamEmptyTags(t *testing.T) {
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-gateway-empty-%d", time.Now().UnixNano()),
		"subdomain": fmt.Sprintf("gateway-empty-%d", time.Now().UnixNano()),
	}
	gatewayID := CreateGateway(t, gatewayPayload)

	// Create an upstream with initial tags
	initialTags := []string{"initial", "test"}
	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-upstream-empty-%d", time.Now().UnixNano()),
		"algorithm": "round-robin",
		"tags":      initialTags,
		"targets": []map[string]interface{}{
			{
				"host":     "example.com",
				"port":     80,
				"protocol": "http",
				"weight":   100,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)
	t.Logf("✅ Upstream created with ID: %s and initial tags: %v", upstreamID, initialTags)

	// Update the upstream with empty tags
	updatePayload := map[string]interface{}{
		"name":      fmt.Sprintf("updated-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"tags":      []string{}, // Empty tags
		"targets": []map[string]interface{}{
			{
				"host":     "updated.example.com",
				"port":     80,
				"protocol": "http",
				"weight":   100,
			},
		},
	}

	// Perform the update
	updateStatus, updateResponse := sendRequest(
		t,
		http.MethodPut,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		updatePayload,
	)

	assert.Equal(t, http.StatusOK, updateStatus)
	if updateStatus != http.StatusOK {
		t.Fatalf("❌ Failed to update upstream. Status: %d, Response: %v", updateStatus, updateResponse)
	}

	// Verify the response has empty tags
	responseTagsInterface, exists := updateResponse["tags"]
	if exists && responseTagsInterface != nil {
		responseTags, ok := responseTagsInterface.([]interface{})
		if ok {
			assert.Empty(t, responseTags, "Response tags should be empty")
		}
	}

	// Fetch from database to verify
	getStatus, getResponse := sendRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		nil,
	)

	assert.Equal(t, http.StatusOK, getStatus)

	// Verify database has empty tags
	dbTagsInterface, exists := getResponse["tags"]
	if exists && dbTagsInterface != nil {
		dbTags, ok := dbTagsInterface.([]interface{})
		if ok {
			assert.Empty(t, dbTags, "Database tags should be empty")
		}
	}

	t.Logf("✅ Update upstream with empty tags test completed successfully")
}

// TestUpdateUpstreamNullTags tests updating upstream with null tags
func TestUpdateUpstreamNullTags(t *testing.T) {
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-gateway-null-%d", time.Now().UnixNano()),
		"subdomain": fmt.Sprintf("gateway-null-%d", time.Now().UnixNano()),
	}
	gatewayID := CreateGateway(t, gatewayPayload)

	// Create an upstream with initial tags
	initialTags := []string{"initial", "test"}
	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("test-upstream-null-%d", time.Now().UnixNano()),
		"algorithm": "round-robin",
		"tags":      initialTags,
		"targets": []map[string]interface{}{
			{
				"host":     "example.com",
				"port":     80,
				"protocol": "http",
				"weight":   100,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)
	t.Logf("✅ Upstream created with ID: %s and initial tags: %v", upstreamID, initialTags)

	// Update the upstream without tags field (null/omitted)
	updatePayload := map[string]interface{}{
		"name":      fmt.Sprintf("updated-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		// Note: tags field is omitted entirely
		"targets": []map[string]interface{}{
			{
				"host":     "updated.example.com",
				"port":     80,
				"protocol": "http",
				"weight":   100,
			},
		},
	}

	// Perform the update
	updateStatus, updateResponse := sendRequest(
		t,
		http.MethodPut,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		updatePayload,
	)

	assert.Equal(t, http.StatusOK, updateStatus)
	if updateStatus != http.StatusOK {
		t.Fatalf("❌ Failed to update upstream. Status: %d, Response: %v", updateStatus, updateResponse)
	}

	// Fetch from database to verify what happened to tags
	getStatus, getResponse := sendRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		nil,
	)

	assert.Equal(t, http.StatusOK, getStatus)

	// Log what happened to tags when omitted from update
	dbTagsInterface, exists := getResponse["tags"]
	if exists {
		t.Logf("✅ Tags field in database after update with omitted tags: %v", dbTagsInterface)
	} else {
		t.Logf("✅ Tags field not present in database response after update with omitted tags")
	}

	t.Logf("✅ Update upstream with null/omitted tags test completed successfully")
}
