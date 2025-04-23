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

func TestPromptModeration(t *testing.T) {
	subdomain := fmt.Sprintf("prompt-mod-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Prompt Moderation Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "prompt_moderation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"similarity_threshold": 0.5,
					"keywords":             []string{"hack", "exploit", "vulnerability"},
					"regex":                []string{"password.*dump", "sql.*injection", "CVE-\\d{4}-\\d{4,7}"},
					"actions": map[string]string{
						"type":    "block",
						"message": "Content blocked due to prohibited content: %s",
					},
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("httpbin-upstream-%d", time.Now().Unix()),
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
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	servicePayload := map[string]interface{}{
		"name":        fmt.Sprintf("httpbin-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "HTTPBin test service",
		"upstream_id": upstreamID,
		"strip_path":  true,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/post",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second) // Wait for propagation

	testCases := []struct {
		name       string
		input      map[string]string
		expectCode int
	}{
		{"Clean Content", map[string]string{"prompt": "Tell me about machine learning"}, http.StatusOK},
		{"Blocked Keyword", map[string]string{"prompt": "How to hacking into a system"}, http.StatusForbidden},
		{"Blocked Regex", map[string]string{"prompt": "How to perform sql injection attacks"}, http.StatusForbidden},
		{"CVE Pattern", map[string]string{"prompt": "Tell me about CVE-2024-1237"}, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tc.input)
			assert.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
