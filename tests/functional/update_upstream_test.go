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
	defer RunTest(t, "UpdateUpstream", time.Now())()
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name": fmt.Sprintf("test-gateway-%d", time.Now().Unix()),
	}
	gatewayID := CreateGateway(t, gatewayPayload)

	// Create an upstream with initial configuration
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
		"health_checks": map[string]interface{}{
			"passive":   true,
			"threshold": 3,
			"interval":  30,
		},
		"websocket_config": map[string]interface{}{
			"enable_direct_communication": true,
			"return_error_details":        false,
			"ping_period":                 "10s",
			"pong_wait":                   "20s",
			"handshake_timeout":           "5s",
			"read_buffer_size":            4096,
			"write_buffer_size":           4096,
		},
		"proxy": map[string]interface{}{
			"host":     "proxy.example.com",
			"port":     "8080",
			"protocol": "http",
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)
	t.Logf("✅ Upstream created with ID: %s", upstreamID)

	// Fetch the initial upstream to capture createdAt and other initial values
	initialGetStatus, initialResponse := sendRequest(
		t,
		http.MethodGet,
		fmt.Sprintf("%s/gateways/%s/upstreams/%s", AdminUrl, gatewayID, upstreamID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		nil,
	)

	assert.Equal(t, http.StatusOK, initialGetStatus)
	if initialGetStatus != http.StatusOK {
		t.Fatalf("❌ Failed to fetch initial upstream. Status: %d", initialGetStatus)
	}

	initialCreatedAt, createdAtExists := initialResponse["created_at"]
	assert.True(t, createdAtExists, "Initial response should contain 'created_at' field")

	initialUpdatedAt, updatedAtExists := initialResponse["updated_at"]
	assert.True(t, updatedAtExists, "Initial response should contain 'updated_at' field")

	t.Logf("✅ Initial createdAt: %v, updatedAt: %v", initialCreatedAt, initialUpdatedAt)

	// Wait a moment to ensure updatedAt will be different
	time.Sleep(1 * time.Second)

	// Update the upstream with new configuration
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
		"health_checks": map[string]interface{}{
			"passive":   false,
			"path":      "/health",
			"threshold": 5,
			"interval":  60,
		},
		"websocket_config": map[string]interface{}{
			"enable_direct_communication": false,
			"return_error_details":        true,
			"ping_period":                 "15s",
			"pong_wait":                   "30s",
			"handshake_timeout":           "10s",
			"read_buffer_size":            8192,
			"write_buffer_size":           8192,
		},
		"proxy": map[string]interface{}{
			"host":     "new-proxy.example.com",
			"port":     "9090",
			"protocol": "https",
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

	t.Logf("✅ Upstream updated successfully")

	// Verify all fields in the update response
	assert.Equal(t, updatePayload["name"], updateResponse["name"], "Response name should match the updated name")
	assert.Equal(t, updatePayload["algorithm"], updateResponse["algorithm"], "Response algorithm should match the updated algorithm")

	// Verify tags
	responseTagsInterface, exists := updateResponse["tags"]
	assert.True(t, exists, "Response should contain 'tags' field")
	if exists {
		responseTags, ok := responseTagsInterface.([]interface{})
		assert.True(t, ok, "Tags should be an array")
		if ok {
			var responseTagsStrings []string
			for _, tag := range responseTags {
				if tagStr, ok := tag.(string); ok {
					responseTagsStrings = append(responseTagsStrings, tagStr)
				}
			}
			assert.ElementsMatch(t, newTags, responseTagsStrings, "Response tags should match the updated tags")
		}
	}

	// Verify targets array
	responseTargetsInterface, targetsExist := updateResponse["targets"]
	assert.True(t, targetsExist, "Response should contain 'targets' field")
	if targetsExist {
		responseTargets, ok := responseTargetsInterface.([]interface{})
		assert.True(t, ok, "Targets should be an array")
		assert.Len(t, responseTargets, 2, "Should have 2 targets after update")
	}

	// Verify health checks
	responseHealthChecks, healthExists := updateResponse["health_checks"]
	assert.True(t, healthExists, "Response should contain 'health_checks' field")
	if healthExists && responseHealthChecks != nil {
		healthMap, ok := responseHealthChecks.(map[string]interface{})
		assert.True(t, ok, "Health checks should be a map")
		if ok {
			assert.Equal(t, false, healthMap["passive"], "Health check passive should be updated")
			assert.Equal(t, "/health", healthMap["path"], "Health check path should be updated")
			assert.Equal(t, float64(5), healthMap["threshold"], "Health check threshold should be updated")
			assert.Equal(t, float64(60), healthMap["interval"], "Health check interval should be updated")
		}
	}

	// Verify websocket config
	responseWebsocket, websocketExists := updateResponse["websocket_config"]
	assert.True(t, websocketExists, "Response should contain 'websocket_config' field")
	if websocketExists && responseWebsocket != nil {
		websocketMap, ok := responseWebsocket.(map[string]interface{})
		assert.True(t, ok, "Websocket config should be a map")
		if ok {
			assert.Equal(t, false, websocketMap["enable_direct_communication"], "Websocket enable_direct_communication should be updated")
			assert.Equal(t, true, websocketMap["return_error_details"], "Websocket return_error_details should be updated")
			assert.Equal(t, "15s", websocketMap["ping_period"], "Websocket ping_period should be updated")
			assert.Equal(t, float64(8192), websocketMap["read_buffer_size"], "Websocket read_buffer_size should be updated")
		}
	}

	// Verify proxy config
	responseProxy, proxyExists := updateResponse["proxy"]
	if proxyExists && responseProxy != nil {
		proxyMap, ok := responseProxy.(map[string]interface{})
		assert.True(t, ok, "Proxy config should be a map")
		if ok {
			assert.Equal(t, "new-proxy.example.com", proxyMap["host"], "Proxy host should be updated")
			assert.Equal(t, "9090", proxyMap["port"], "Proxy port should be updated")
			assert.Equal(t, "https", proxyMap["protocol"], "Proxy protocol should be updated")
		}
	}

	// CRITICAL: Verify createdAt is unchanged and updatedAt is changed
	responseCreatedAt, responseCreatedAtExists := updateResponse["created_at"]
	assert.True(t, responseCreatedAtExists, "Response should contain 'created_at' field")

	responseUpdatedAt, responseUpdatedAtExists := updateResponse["updated_at"]
	assert.True(t, responseUpdatedAtExists, "Response should contain 'updated_at' field")
	assert.NotEqual(t, initialUpdatedAt, responseUpdatedAt, "updatedAt should change during update")

	// Parse timestamps for more flexible comparison (handle nanosecond precision differences)
	initialCreatedAtStr, ok := initialCreatedAt.(string)
	if !ok {
		initialCreatedAtStr = ""
	}
	responseCreatedAtStr, ok := responseCreatedAt.(string)
	if !ok {
		responseCreatedAtStr = ""
	}

	if initialCreatedAtStr != "" && responseCreatedAtStr != "" {
		initialTime, err1 := time.Parse(time.RFC3339Nano, initialCreatedAtStr)
		responseTime, err2 := time.Parse(time.RFC3339Nano, responseCreatedAtStr)

		if err1 == nil && err2 == nil {
			// Allow for small timestamp precision differences (within 1 second)
			timeDiff := responseTime.Sub(initialTime).Abs()
			assert.True(t, timeDiff < time.Second, "createdAt should be essentially unchanged (diff: %v)", timeDiff)
		} else {
			// Fallback to string comparison if parsing fails
			assert.Equal(t, initialCreatedAt, responseCreatedAt, "createdAt should NOT change during update")
		}
	}

	t.Logf("✅ Timestamp verification: createdAt preserved (%v), updatedAt changed (%v -> %v)",
		initialCreatedAt, initialUpdatedAt, responseUpdatedAt)

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
		t.Fatalf("❌ Failed to fetch updated upstream. Status: %d, Response: %v", getStatus, getResponse)
	}

	// Final comprehensive checks - verify database matches update response
	assert.Equal(t, updateResponse["name"], getResponse["name"], "Database name should match update response")
	assert.Equal(t, updateResponse["algorithm"], getResponse["algorithm"], "Database algorithm should match update response")
	assert.Equal(t, updateResponse["id"], getResponse["id"], "Database ID should match update response")
	assert.Equal(t, updateResponse["created_at"], getResponse["created_at"], "Database createdAt should match update response")
	assert.Equal(t, updateResponse["updated_at"], getResponse["updated_at"], "Database updatedAt should match update response")

	// Verify database also preserves createdAt immutability
	dbCreatedAt, dbCreatedAtExists := getResponse["created_at"]
	assert.True(t, dbCreatedAtExists, "Database response should contain 'created_at' field")

	// Use flexible timestamp comparison for database as well
	dbCreatedAtStr, ok := dbCreatedAt.(string)
	if !ok {
		dbCreatedAtStr = ""
	}
	if initialCreatedAtStr != "" && dbCreatedAtStr != "" {
		initialTime, err1 := time.Parse(time.RFC3339Nano, initialCreatedAtStr)
		dbTime, err2 := time.Parse(time.RFC3339Nano, dbCreatedAtStr)

		if err1 == nil && err2 == nil {
			// Allow for small timestamp precision differences (within 1 second)
			timeDiff := dbTime.Sub(initialTime).Abs()
			assert.True(t, timeDiff < time.Second, "Database createdAt should be essentially unchanged from original (diff: %v)", timeDiff)
		} else {
			// Fallback to string comparison if parsing fails
			assert.Equal(t, initialCreatedAt, dbCreatedAt, "Database createdAt should be unchanged from original")
		}
	}

	dbUpdatedAt, dbUpdatedAtExists := getResponse["updated_at"]
	assert.True(t, dbUpdatedAtExists, "Database response should contain 'updated_at' field")
	assert.NotEqual(t, initialUpdatedAt, dbUpdatedAt, "Database updatedAt should be different from original")

	t.Logf("✅ Update upstream comprehensive test completed successfully")
}

func TestUpdateUpstreamEmptyTags(t *testing.T) {
	defer RunTest(t, "UpdateUpstream", time.Now())()
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name": fmt.Sprintf("test-gateway-empty-%d", time.Now().UnixNano()),
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
	defer RunTest(t, "UpdateUpstream", time.Now())()
	// Create a gateway
	gatewayPayload := map[string]interface{}{
		"name": fmt.Sprintf("test-gateway-null-%d", time.Now().UnixNano()),
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
