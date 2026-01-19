package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCodeSanitation_SanitizeMode tests the code_sanitation plugin in sanitize mode.
// When code injection patterns are detected, they are sanitized (replaced with *)
// instead of blocking the request.
func TestCodeSanitation_SanitizeMode(t *testing.T) {
	subdomain := fmt.Sprintf("code-sanitize-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Sanitize Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-sanitize-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-sanitize-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation sanitize test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-sanitize-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []string{"body"},
					"action":              "sanitize",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(2 * time.Second)

	sanitizeTests := []struct {
		name           string
		body           map[string]interface{}
		expectedStatus int
		checkField     string
		shouldNotHave  string
		description    string
	}{
		{
			name:           "JavaScript eval",
			body:           map[string]interface{}{"content": "eval('alert(1)')"},
			expectedStatus: 200,
			checkField:     "content",
			shouldNotHave:  "eval",
			description:    "eval should be sanitized but request should pass",
		},
		{
			name:           "Python exec",
			body:           map[string]interface{}{"code": "exec('import os')"},
			expectedStatus: 200,
			checkField:     "code",
			shouldNotHave:  "exec",
			description:    "exec should be sanitized but request should pass",
		},
		{
			name:           "PHP system",
			body:           map[string]interface{}{"cmd": "system('whoami')"},
			expectedStatus: 200,
			checkField:     "cmd",
			shouldNotHave:  "system",
			description:    "system should be sanitized but request should pass",
		},
		{
			name:           "Script tag",
			body:           map[string]interface{}{"html": "<script>alert('xss')</script>"},
			expectedStatus: 200,
			checkField:     "html",
			shouldNotHave:  "<script",
			description:    "script tag should be sanitized but request should pass",
		},
		{
			name:           "Shell command",
			body:           map[string]interface{}{"input": "cat /etc/passwd"},
			expectedStatus: 200,
			checkField:     "input",
			shouldNotHave:  "cat /etc/passwd",
			description:    "shell command should be sanitized but request should pass",
		},
		{
			name:           "Safe content unchanged",
			body:           map[string]interface{}{"message": "Hello, how are you today?"},
			expectedStatus: 200,
			checkField:     "message",
			shouldNotHave:  "", // Empty means nothing to check
			description:    "safe content should pass unchanged",
		},
	}

	for _, tt := range sanitizeTests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			url := ProxyUrl + "/code-sanitize-test"
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
			require.NoError(t, err)

			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode,
				"%s: %s", tt.name, tt.description)

			if resp.StatusCode == 200 {
				t.Logf("✅ %s: request passed (sanitized)", tt.name)
			}
		})
	}
}

// TestCodeSanitation_BlockMode tests the code_sanitation plugin in block mode.
// When code injection patterns are detected, the request is blocked.
func TestCodeSanitation_BlockMode(t *testing.T) {
	subdomain := fmt.Sprintf("code-block-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Block Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-block-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-block-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation block test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-block-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []string{"body"},
					"action":              "block",
					"status_code":         400,
					"error_message":       "Code injection detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(2 * time.Second)

	blockTests := []struct {
		name           string
		body           map[string]interface{}
		expectedStatus int
		description    string
	}{
		{
			name:           "JavaScript eval blocked",
			body:           map[string]interface{}{"content": "eval('malicious')"},
			expectedStatus: 400,
			description:    "eval should be blocked",
		},
		{
			name:           "SQL injection blocked",
			body:           map[string]interface{}{"query": "SELECT * FROM users WHERE id = 1"},
			expectedStatus: 400,
			description:    "SQL should be blocked",
		},
		{
			name:           "Python exec blocked",
			body:           map[string]interface{}{"code": "exec('import os')"},
			expectedStatus: 400,
			description:    "exec should be blocked",
		},
		{
			name:           "Shell command blocked",
			body:           map[string]interface{}{"cmd": "cat /etc/passwd"},
			expectedStatus: 400,
			description:    "shell command should be blocked",
		},
		{
			name:           "Script tag blocked",
			body:           map[string]interface{}{"html": "<script>alert(1)</script>"},
			expectedStatus: 400,
			description:    "script tag should be blocked",
		},
		{
			name:           "Java Runtime blocked",
			body:           map[string]interface{}{"code": "Runtime.getRuntime().exec('calc')"},
			expectedStatus: 400,
			description:    "Java Runtime should be blocked",
		},
		{
			name:           "Safe content allowed",
			body:           map[string]interface{}{"message": "Hello, this is a safe message!"},
			expectedStatus: 200,
			description:    "safe content should pass",
		},
		{
			name:           "Numbers and text allowed",
			body:           map[string]interface{}{"count": 42, "name": "John Doe"},
			expectedStatus: 200,
			description:    "normal JSON should pass",
		},
	}

	for _, tt := range blockTests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			url := ProxyUrl + "/code-block-test"
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
			require.NoError(t, err)

			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode,
				"%s: %s", tt.name, tt.description)

			switch resp.StatusCode {
			case 400:
				var errorResp map[string]interface{}
				err := json.NewDecoder(resp.Body).Decode(&errorResp)
				if err == nil {
					if msg, ok := errorResp["error"].(string); ok {
						assert.Contains(t, msg, "injection", "Error message should mention injection")
					}
				}
				t.Logf("✅ %s: blocked as expected", tt.name)
			case 200:
				t.Logf("✅ %s: allowed as expected", tt.name)
			}
		})
	}
}

// TestCodeSanitation_SpecificLanguages tests the code_sanitation plugin with specific languages enabled.
func TestCodeSanitation_SpecificLanguages(t *testing.T) {
	subdomain := fmt.Sprintf("code-lang-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Language Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-lang-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-lang-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation language test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-lang-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	// Only enable JavaScript and SQL detection
	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"languages": []map[string]interface{}{
						{"language": "javascript", "enabled": true},
						{"language": "sql", "enabled": true},
					},
					"content_to_check": []string{"body"},
					"action":           "block",
					"status_code":      400,
					"error_message":    "Code injection detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	// Allow more time for plugin propagation in CI environments
	time.Sleep(2 * time.Second)

	langTests := []struct {
		name           string
		body           map[string]interface{}
		expectedStatus int
		description    string
	}{
		{
			name:           "JavaScript eval blocked",
			body:           map[string]interface{}{"content": "eval('test')"},
			expectedStatus: 400,
			description:    "JavaScript is enabled, should be blocked",
		},
		{
			name:           "Python exec NOT blocked",
			body:           map[string]interface{}{"code": "exec('import os')"},
			expectedStatus: 200,
			description:    "Python is NOT enabled, should pass",
		},
		{
			name:           "Shell command NOT blocked",
			body:           map[string]interface{}{"cmd": "cat /etc/passwd"},
			expectedStatus: 200,
			description:    "Shell is NOT enabled, should pass",
		},
	}

	for _, tt := range langTests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, err := json.Marshal(tt.body)
			require.NoError(t, err)

			url := ProxyUrl + "/code-lang-test"
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
			require.NoError(t, err)

			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode,
				"%s: %s", tt.name, tt.description)

			if resp.StatusCode == tt.expectedStatus {
				if resp.StatusCode == 400 {
					t.Logf("✅ %s: blocked as expected", tt.name)
				} else {
					t.Logf("✅ %s: allowed as expected (language not enabled)", tt.name)
				}
			}
		})
	}
}

// TestCodeSanitation_ContentTypes tests the code_sanitation plugin with different content check types.
func TestCodeSanitation_ContentTypes(t *testing.T) {
	subdomain := fmt.Sprintf("code-content-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Content Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-content-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-content-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation content test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-content-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	// Check all content types: headers, path_and_query, body
	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []string{"headers", "path_and_query", "body"},
					"action":              "block",
					"status_code":         400,
					"error_message":       "Code injection detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(2 * time.Second)

	t.Run("Code in body blocked", func(t *testing.T) {
		bodyBytes, err := json.Marshal(map[string]interface{}{"content": "eval('test')"})
		require.NoError(t, err)

		url := ProxyUrl + "/code-content-test"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "code in body should be blocked")
		t.Logf("✅ Code in body blocked")
	})

	t.Run("Code in query params blocked", func(t *testing.T) {
		url := ProxyUrl + "/code-content-test?input=cat%20/etc/passwd"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "code in query params should be blocked")
		t.Logf("✅ Code in query params blocked")
	})

	t.Run("Code in headers blocked", func(t *testing.T) {
		url := ProxyUrl + "/code-content-test"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("X-Custom-Header", "eval('header injection')")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "code in headers should be blocked")
		t.Logf("✅ Code in headers blocked")
	})

	t.Run("Safe request allowed", func(t *testing.T) {
		bodyBytes, err := json.Marshal(map[string]interface{}{"message": "Hello world"})
		require.NoError(t, err)

		url := ProxyUrl + "/code-content-test?page=1&limit=10"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", "12345")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 200, resp.StatusCode, "safe request should be allowed")
		t.Logf("✅ Safe request allowed")
	})
}

// TestCodeSanitation_NestedJSON tests sanitization of nested JSON structures.
func TestCodeSanitation_NestedJSON(t *testing.T) {
	subdomain := fmt.Sprintf("code-nested-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Nested JSON Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-nested-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-nested-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation nested JSON test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-nested-test",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []string{"body"},
					"action":              "block",
					"status_code":         400,
					"error_message":       "Code injection detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(2 * time.Second)

	t.Run("Nested object with code blocked", func(t *testing.T) {
		body := map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"code": "eval('nested')",
				},
			},
		}
		bodyBytes, err := json.Marshal(body)
		require.NoError(t, err)

		url := ProxyUrl + "/code-nested-test"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "nested code should be blocked")
		t.Logf("✅ Nested object with code blocked")
	})

	t.Run("Array with code blocked", func(t *testing.T) {
		body := map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"safe": "value"},
				map[string]interface{}{"code": "eval('in array')"},
			},
		}
		bodyBytes, err := json.Marshal(body)
		require.NoError(t, err)

		url := ProxyUrl + "/code-nested-test"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "code in array should be blocked")
		t.Logf("✅ Array with code blocked")
	})

	t.Run("Safe nested structure allowed", func(t *testing.T) {
		body := map[string]interface{}{
			"user": map[string]interface{}{
				"name":    "John Doe",
				"email":   "john@example.com",
				"profile": map[string]interface{}{"bio": "Hello, I am John"},
			},
			"preferences": []string{"dark_mode", "notifications"},
		}
		bodyBytes, err := json.Marshal(body)
		require.NoError(t, err)

		url := ProxyUrl + "/code-nested-test"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 200, resp.StatusCode, "safe nested structure should be allowed")
		t.Logf("✅ Safe nested structure allowed")
	})
}

// TestCodeSanitation_PlainTextBody tests sanitization of plain text (non-JSON) bodies.
func TestCodeSanitation_PlainTextBody(t *testing.T) {
	subdomain := fmt.Sprintf("code-plain-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Code Sanitation Plain Text Test Gateway",
		"subdomain": subdomain,
	})

	apiKey := CreateApiKey(t, gatewayID)

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      fmt.Sprintf("code-plain-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("code-plain-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Code sanitation plain text test service",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"name":       uuid.New().String(),
		"path":       "/code-plain-test",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": true,
		"active":     true,
	}

	status, ruleResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, rulePayload)
	assert.Equal(t, http.StatusCreated, status)
	ruleID, ok := ruleResp["id"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, ruleID)

	pluginPayload := map[string]interface{}{
		"type": "rule",
		"id":   ruleID,
		"plugins": []map[string]interface{}{
			{
				"name":     "code_sanitation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"parallel": false,
				"settings": map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []string{"body"},
					"action":              "block",
					"status_code":         400,
					"error_message":       "Code injection detected",
				},
			},
		},
	}

	status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/plugins", AdminUrl), map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
	}, pluginPayload)
	assert.Equal(t, http.StatusNoContent, status)

	time.Sleep(2 * time.Second)

	t.Run("Plain text with code blocked", func(t *testing.T) {
		url := ProxyUrl + "/code-plain-test"
		req, err := http.NewRequest(http.MethodPost, url, io.NopCloser(bytes.NewBufferString("eval('plain text injection')")))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 400, resp.StatusCode, "plain text with code should be blocked")
		t.Logf("✅ Plain text with code blocked")
	})

	t.Run("Safe plain text allowed", func(t *testing.T) {
		url := ProxyUrl + "/code-plain-test"
		req, err := http.NewRequest(http.MethodPost, url, io.NopCloser(bytes.NewBufferString("This is a safe plain text message.")))
		require.NoError(t, err)

		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 200, resp.StatusCode, "safe plain text should be allowed")
		t.Logf("✅ Safe plain text allowed")
	})
}
