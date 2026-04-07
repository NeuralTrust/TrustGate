package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInvalidRequestBody_Returns400 verifies that sending a malformed request
// body to a provider-backed upstream returns HTTP 400 (Bad Request) with a
// user-friendly error message, instead of the previous behaviour of returning
// 502 (Bad Gateway) with raw JSON parsing internals leaked in the response.
func TestInvalidRequestBody_Returns400(t *testing.T) {
	defer RunTest(t, "InvalidRequestBody", time.Now())()

	subdomain := fmt.Sprintf("invalid-body-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Invalid Request Body Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("invalid-body-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"provider":      "google",
				"weight":        100,
				"priority":      1,
				"default_model": "gemini-2.0-flash-001",
				"models":        []string{"gemini-2.0-flash-001"},
				"credentials":   map[string]string{"api_key": "fake-key-for-decode-test"},
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("invalid-body-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Invalid request body test service",
		"upstream_id": upstreamID,
	})

	CreateRules(t, gatewayID, map[string]interface{}{
		"path":       "/v1/chat/completions",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
	})

	time.Sleep(2 * time.Second)

	host := fmt.Sprintf("%s.%s", subdomain, BaseDomain)

	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
		wantError   string
	}{
		{
			name:        "completely invalid JSON",
			body:        `{this is not json at all}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid request body",
		},
		{
			name:        "truncated JSON",
			body:        `{"model": "gpt-4", "messages": [{"role": "user", "content":`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid request body",
		},
		{
			name:        "temperature as string instead of number",
			body:        `{"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}], "temperature": "hot"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid request body",
		},
		{
			name:        "binary-like garbage",
			body:        "\x00\x01\x02\x03\x04",
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantError:   "invalid request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(
				http.MethodPost,
				ProxyUrl+"/v1/chat/completions",
				io.NopCloser(strings.NewReader(tt.body)),
			)
			require.NoError(t, err)

			req.Host = host
			req.Header.Set("Host", host)
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", tt.contentType)

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.wantStatus, resp.StatusCode,
				"expected %d but got %d", tt.wantStatus, resp.StatusCode)

			respBytes, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var respData map[string]interface{}
			if json.Unmarshal(respBytes, &respData) == nil {
				errorMsg, _ := respData["error"].(string)

				assert.Contains(t, errorMsg, tt.wantError,
					"error message should contain %q, got: %s", tt.wantError, errorMsg)

				assert.NotContains(t, errorMsg, "invalid character",
					"error should NOT leak raw JSON parsing details")
				assert.NotContains(t, errorMsg, "numeric literal",
					"error should NOT leak raw JSON parsing details")
			}

			t.Logf("got %d with body: %s", resp.StatusCode, string(respBytes))
		})
	}

	t.Run("valid OpenAI body is NOT rejected as 400", func(t *testing.T) {
		validBody, _ := json.Marshal(map[string]interface{}{
			"model":    "gemini-2.0-flash-001",
			"messages": []map[string]string{{"role": "user", "content": "hello"}},
		})

		req, err := http.NewRequest(
			http.MethodPost,
			ProxyUrl+"/v1/chat/completions",
			bytes.NewReader(validBody),
		)
		require.NoError(t, err)

		req.Host = host
		req.Header.Set("Host", host)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode,
			"valid body should NOT return 400; got %d (may be 401/502 with fake key, but not 400)",
		)

		t.Logf("valid body returned status %d (expected anything except 400)", resp.StatusCode)
	})
}
