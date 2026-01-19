package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestQueryParamsForwarding(t *testing.T) {
	defer RunTest(t, "QueryParams", time.Now())()
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Query Params Test Gateway",
		"subdomain": fmt.Sprintf("query-params-test-%d", time.Now().UnixNano()),
	})

	// Create upstream pointing to ping endpoint
	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Query Params Upstream",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Query Params Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"path":       "/ping",
		"name":       "query-params-rule",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": false,
	}
	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, ruleResp["id"])

	apiKey := CreateApiKey(t, gatewayID)

	// Wait for propagation
	time.Sleep(500 * time.Millisecond)

	t.Run("GET request with query params should forward them to upstream", func(t *testing.T) {
		queryParams := url.Values{}
		queryParams.Set("param1", "value1")
		queryParams.Set("param2", "value2")
		queryParams.Set("test", "query")

		reqURL := fmt.Sprintf("%s/ping?%s", ProxyUrl, queryParams.Encode())
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)

		// Verify message
		assert.Equal(t, "pong", response["message"])

		// Verify query params are present in response
		queryParamsResp, ok := response["query_params"].(map[string]interface{})
		assert.True(t, ok, "Response should contain query_params")
		assert.NotNil(t, queryParamsResp, "query_params should not be nil")

		// Verify each query param value
		assert.Equal(t, "value1", queryParamsResp["param1"], "param1 should match")
		assert.Equal(t, "value2", queryParamsResp["param2"], "param2 should match")
		assert.Equal(t, "query", queryParamsResp["test"], "test should match")
	})

	t.Run("POST request with query params should forward them to upstream", func(t *testing.T) {
		queryParams := url.Values{}
		queryParams.Set("foo", "bar")
		queryParams.Set("baz", "qux")

		requestBody := map[string]interface{}{
			"test": "data",
		}
		bodyBytes, err := json.Marshal(requestBody)
		assert.NoError(t, err)

		reqURL := fmt.Sprintf("%s/ping?%s", ProxyUrl, queryParams.Encode())
		req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewBuffer(bodyBytes))
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)

		// Verify message
		assert.Equal(t, "pong", response["message"])

		// Verify query params are present in response
		queryParamsResp, ok := response["query_params"].(map[string]interface{})
		assert.True(t, ok, "Response should contain query_params")
		assert.NotNil(t, queryParamsResp, "query_params should not be nil")

		// Verify each query param value
		assert.Equal(t, "bar", queryParamsResp["foo"], "foo should match")
		assert.Equal(t, "qux", queryParamsResp["baz"], "baz should match")
	})

	t.Run("request without query params should not include query_params in response", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/ping", ProxyUrl), nil)
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)

		// Verify message
		assert.Equal(t, "pong", response["message"])

		// Verify query_params is not present in response
		_, ok := response["query_params"]
		assert.False(t, ok, "query_params should not be present when no query params are sent")
	})

	t.Run("request with special characters in query params should forward them correctly", func(t *testing.T) {
		queryParams := url.Values{}
		queryParams.Set("special", "value with spaces")
		queryParams.Set("encoded", "test%20value")
		queryParams.Set("number", "123")

		reqURL := fmt.Sprintf("%s/ping?%s", ProxyUrl, queryParams.Encode())
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)

		// Verify message
		assert.Equal(t, "pong", response["message"])

		// Verify query params are present in response
		queryParamsResp, ok := response["query_params"].(map[string]interface{})
		assert.True(t, ok, "Response should contain query_params")
		assert.NotNil(t, queryParamsResp, "query_params should not be nil")

		// Verify special characters are handled correctly
		assert.Equal(t, "value with spaces", queryParamsResp["special"], "special should match")
		assert.Equal(t, "test%20value", queryParamsResp["encoded"], "encoded should match")
		assert.Equal(t, "123", queryParamsResp["number"], "number should match")
	})
}
