package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func CreateGateway(t *testing.T, gatewayPayload map[string]interface{}) string {
	status, gatewayResp := sendRequest(
		t,
		http.MethodPost, AdminUrl+"/gateways",
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		gatewayPayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create gateway. Status: %d, Response: %v", status, gatewayResp)
	}

	gatewayID, ok := gatewayResp["id"].(string)
	assert.True(t, ok)
	if gatewayID == "" {
		t.Fatalf("❌ Gateway creation response did not contain a valid ID. Response: %v", gatewayResp)
	}

	t.Logf("✅ Gateway created with ID: %s", gatewayID)
	return gatewayID
}

func CreateApiKey(t *testing.T, gatewayID string) string {
	apiKeyPayload := map[string]interface{}{
		"name":         "Test Key",
		"expires_at":   "2066-01-01T00:00:00Z",
		"subject":      gatewayID,
		"subject_type": "gateway",
	}
	status, apiKeyResp := sendRequest(
		t,
		http.MethodPost,
		fmt.Sprintf("%s/iam/api-keys", AdminUrl),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		apiKeyPayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create apiKey. Status: %d, Response: %v", status, apiKeyResp)
	}

	apiKey, ok := apiKeyResp["key"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, apiKey)
	t.Logf("✅ API Key created: %s\n", apiKey)
	return apiKey
}

func CreateUpstream(t *testing.T, gatewayID string, upstreamPayload map[string]interface{}) string {
	status, upstreamResp := sendRequest(
		t,
		http.MethodPost,
		fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		upstreamPayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create upstream. Status: %d, Response: %v", status, upstreamResp)
	}

	upstreamID, ok := upstreamResp["id"].(string)
	assert.True(t, ok)
	if upstreamID == "" {
		t.Fatalf("❌ Upstream creation response did not contain a valid ID. Response: %v", upstreamResp)
	}

	t.Logf("✅ Upstream created with ID: %s", upstreamID)
	return upstreamID
}

func CreateService(t *testing.T, gatewayID string, servicePayload map[string]interface{}) string {
	status, serviceResp := sendRequest(
		t,
		http.MethodPost,
		fmt.Sprintf("%s/gateways/%s/services", AdminUrl, gatewayID),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		servicePayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create service. Status: %d, Response: %v", status, serviceResp)
	}

	serviceID, ok := serviceResp["id"].(string)
	assert.True(t, ok)
	if serviceID == "" {
		t.Fatalf("❌ Service creation response did not contain a valid ID. Response: %v", serviceResp)
	}

	t.Logf("✅ Service created with ID: %s", serviceID)

	return serviceID
}

func CreateRules(t *testing.T, gatewayID string, rulesPayload map[string]interface{}) {
	rulesPayload["name"] = uuid.New().String()
	status, rulesResp := sendRequest(
		t,
		http.MethodPost,
		fmt.Sprintf("%s/gateways/%s/rules",
			AdminUrl,
			gatewayID,
		),
		map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		},
		rulesPayload,
	)
	assert.Equal(t, http.StatusCreated, status)
	if status != http.StatusCreated {
		t.Fatalf("❌ Failed to create rules. Status: %d, Response: %v", status, rulesResp)
	}
	t.Logf("✅ Rules created for gateway: %s", gatewayID)
}

func sendRequest(t *testing.T, method, url string, headers map[string]string, body interface{}) (int, map[string]interface{}) {
	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		assert.NoError(t, err)
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, reqBody)
	assert.NoError(t, err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if len(headers) > 0 {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// For 204 No Content responses, return empty map
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, map[string]interface{}{}
	}

	// Read response body
	respBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	var respData map[string]interface{}
	err = json.Unmarshal(respBytes, &respData)
	assert.NoError(t, err)

	return resp.StatusCode, respData
}
