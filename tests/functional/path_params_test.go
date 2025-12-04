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

func TestPathParams(t *testing.T) {
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Path Params Test Gateway",
		"subdomain": fmt.Sprintf("path-params-test-%d", time.Now().UnixNano()),
	})

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Path Params Upstream",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/{id}/mirror",
				"weight":   100,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Path Params Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"path":       "/test/{id}",
		"name":       "path-params-rule",
		"service_id": serviceID,
		"methods":    []string{"POST"},
	}
	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	assert.NotEmpty(t, ruleResp["id"])

	apiKey := CreateApiKey(t, gatewayID)

	time.Sleep(500 * time.Millisecond)

	t.Run("path params should be extracted and passed to upstream", func(t *testing.T) {
		testID := "12345"
		requestBody := map[string]interface{}{
			"test": "data",
		}
		bodyBytes, err := json.Marshal(requestBody)
		assert.NoError(t, err)

		req, err := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/test/%s", ProxyUrl, testID),
			bytes.NewBuffer(bodyBytes),
		)
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

		assert.Equal(t, testID, response["params"], "Path parameter should match the request ID")
		assert.NotNil(t, response["body"], "Response should contain body")
	})

	t.Run("path params with different values should work correctly", func(t *testing.T) {
		testCases := []struct {
			id   string
			name string
		}{
			{"abc123", "alphanumeric"},
			{"user-456", "with-dash"},
			{"test_789", "with-underscore"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				requestBody := map[string]interface{}{
					"test": tc.name,
				}
				bodyBytes, err := json.Marshal(requestBody)
				assert.NoError(t, err)

				req, err := http.NewRequest(
					http.MethodPost,
					fmt.Sprintf("%s/test/%s", ProxyUrl, tc.id),
					bytes.NewBuffer(bodyBytes),
				)
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

				assert.Equal(t, tc.id, response["params"], "Path parameter should match the request ID")
			})
		}
	})

	t.Run("path params should not be replaced if not in forwarding rule", func(t *testing.T) {
		upstreamID2 := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Path Params Upstream 2",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     8081,
					"protocol": "http",
					"path":     "/{user_id}/mirror",
					"weight":   100,
				},
			},
		})

		serviceID2 := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Path Params Service 2",
			"type":        "upstream",
			"upstream_id": upstreamID2,
		})

		rulePayload2 := map[string]interface{}{
			"path":       "/simple",
			"name":       "simple-rule",
			"service_id": serviceID2,
			"methods":    []string{"POST"},
		}
		status2, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, rulePayload2)
		assert.Equal(t, http.StatusCreated, status2)

		time.Sleep(500 * time.Millisecond)

		requestBody := map[string]interface{}{
			"test": "data",
		}
		bodyBytes, err := json.Marshal(requestBody)
		assert.NoError(t, err)

		req, err := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/simple", ProxyUrl),
			bytes.NewBuffer(bodyBytes),
		)
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Request should succeed")

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)

		paramsValue, ok := response["params"].(string)
		assert.True(t, ok, "Params should be a string")

		decodedParam, err := url.QueryUnescape(paramsValue)
		assert.NoError(t, err)
		assert.Equal(t, "{user_id}", decodedParam, "Path parameter should be literal {user_id} (URL-decoded) because it was not extracted from forwarding rule")
	})
}
