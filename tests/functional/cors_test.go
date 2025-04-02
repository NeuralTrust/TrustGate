package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCORSPlugin(t *testing.T) {
	subdomain := fmt.Sprintf("cors-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "CORS Test Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "cors",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"allowed_origins":   []string{"https://allowed.com"},
					"allowed_methods":   []string{"GET", "POST"},
					"allow_credentials": false,
					"max_age":           "600s",
					"expose_headers":    []string{"X-Test"},
					"log_violations":    true,
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("cors-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "httpbin.org",
				"port":     443,
				"protocol": "https",
				"weight":   100,
				"priority": 1,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	servicePayload := map[string]interface{}{
		"name":        fmt.Sprintf("cors-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "CORS test service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/cors-test",
		"service_id": serviceID,
		"methods":    []string{"GET", "POST", "OPTIONS"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)

	tests := []struct {
		name              string
		method            string
		origin            string
		reqHeaders        map[string]string
		expectStatus      int
		expectAllowOrigin string
	}{
		{
			name:              "Valid Origin Simple Request",
			method:            "GET",
			origin:            "https://allowed.com",
			expectStatus:      http.StatusOK,
			expectAllowOrigin: "https://allowed.com",
		},
		{
			name:         "Invalid Origin Simple Request",
			method:       "GET",
			origin:       "https://evil.com",
			expectStatus: http.StatusForbidden,
		},
		{
			name:              "No Origin Header (non-CORS)",
			method:            "GET",
			origin:            "",
			expectStatus:      http.StatusOK,
			expectAllowOrigin: "",
		},
		{
			name:   "Valid Preflight Request",
			method: "OPTIONS",
			origin: "https://allowed.com",
			reqHeaders: map[string]string{
				"Access-Control-Request-Method": "POST",
			},
			expectStatus:      http.StatusNoContent,
			expectAllowOrigin: "https://allowed.com",
		},
		{
			name:   "Invalid Preflight Method",
			method: "OPTIONS",
			origin: "https://allowed.com",
			reqHeaders: map[string]string{
				"Access-Control-Request-Method": "DELETE",
			},
			expectStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "Missing Access-Control-Request-Method Header",
			method:       "OPTIONS",
			origin:       "https://allowed.com",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:   "Invalid Preflight Origin",
			method: "OPTIONS",
			origin: "https://evil.com",
			reqHeaders: map[string]string{
				"Access-Control-Request-Method": "POST",
			},
			expectStatus: http.StatusForbidden,
		},
	}

	client := &http.Client{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, ProxyUrl+"/cors-test", nil)
			assert.NoError(t, err)

			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			for k, v := range tt.reqHeaders {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			if tt.expectAllowOrigin != "" {
				allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				assert.Equal(t, tt.expectAllowOrigin, allowOrigin)
			}
		})
	}

	fmt.Println("\n✅ CORS Plugin Functional Test Completed")
}
