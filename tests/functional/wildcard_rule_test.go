package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWildcardRules(t *testing.T) {
	defer RunTest(t, "WildcardRules", time.Now())()

	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Wildcard Rules Test Gateway",
		"subdomain": fmt.Sprintf("wildcard-test-%d", time.Now().UnixNano()),
	})

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Wildcard Test Upstream",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
				"weight":   100,
			},
		},
	})

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        "Wildcard Test Service",
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	createRule := func(t *testing.T, path string) (int, map[string]interface{}) {
		t.Helper()
		return sendRequest(
			t,
			http.MethodPost,
			fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			map[string]interface{}{
				"path":       path,
				"name":       fmt.Sprintf("rule-%d", time.Now().UnixNano()),
				"service_id": serviceID,
				"methods":    []string{"GET", "POST"},
			},
		)
	}

	t.Run("static paths baseline", func(t *testing.T) {
		status, resp := createRule(t, "/static/users")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/static/users/list")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("param paths without wildcard", func(t *testing.T) {
		status, resp := createRule(t, "/params/users/{id}")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/params/{version}/users/{id}")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("valid wildcard paths", func(t *testing.T) {
		status, resp := createRule(t, "/wc-valid/api/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/wc-valid/api/v1/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/wc-valid/api/{id}/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("invalid wildcard mid-path", func(t *testing.T) {
		status, resp := createRule(t, "/invalid/*/users")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotNil(t, resp["error"])
	})

	t.Run("invalid multiple wildcards", func(t *testing.T) {
		status, resp := createRule(t, "/invalid/*/*")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotNil(t, resp["error"])
	})

	t.Run("invalid wildcards scattered", func(t *testing.T) {
		status, resp := createRule(t, "/invalid/*/users/*")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.NotNil(t, resp["error"])
	})

	t.Run("duplicate wildcard path rejected", func(t *testing.T) {
		status, resp := createRule(t, "/dup-wc/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/dup-wc/*")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "rule already exists", resp["error"])
	})

	t.Run("different wildcard depths are not duplicates", func(t *testing.T) {
		status, resp := createRule(t, "/depth/api/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/depth/api/v1/*")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("normalized param duplicate rejected", func(t *testing.T) {
		status, resp := createRule(t, "/norm/users/{id}")
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		status, resp = createRule(t, "/norm/users/{name}")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "rule already exists", resp["error"])
	})

	t.Run("wildcard proxying with strip_path", func(t *testing.T) {
		wcUpstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Wildcard Strip Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     8081,
					"protocol": "http",
					"path":     "/__/mirror",
					"weight":   100,
				},
			},
		})

		wcServiceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Wildcard Strip Service",
			"type":        "upstream",
			"upstream_id": wcUpstreamID,
		})

		status, resp := sendRequest(
			t,
			http.MethodPost,
			fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID),
			map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
			},
			map[string]interface{}{
				"path":       "/proxy-wc/*",
				"name":       fmt.Sprintf("wc-strip-%d", time.Now().UnixNano()),
				"service_id": wcServiceID,
				"methods":    []string{"GET", "POST"},
				"strip_path": true,
			},
		)
		assert.Equal(t, http.StatusCreated, status)
		assert.NotEmpty(t, resp["id"])

		apiKey := CreateApiKey(t, gatewayID)
		time.Sleep(500 * time.Millisecond)

		body := map[string]interface{}{"test": "wildcard"}
		bodyBytes, err := json.Marshal(body)
		assert.NoError(t, err)

		req, err := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/proxy-wc/hello/world", ProxyUrl),
			bytes.NewBuffer(bodyBytes),
		)
		assert.NoError(t, err)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp2, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp2.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp2.StatusCode,
			"wildcard rule should forward request successfully")
	})
}
