package functional_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBedrockGuardrailPlugin(t *testing.T) {
	subdomain := fmt.Sprintf("bedrock-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Bedrock Guardrail Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "bedrock_guardrail",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"guardrail_id": os.Getenv("GUARDRAIL_ID"),
					"version":      os.Getenv("GUARDRAIL_VERSION"),
					"credentials": map[string]string{
						"aws_access_key": os.Getenv("AWS_ACCESS_KEY"),
						"aws_secret_key": os.Getenv("AWS_SECRET_KEY"),
						"aws_region":     os.Getenv("AWS_REGION"),
					},
					"actions": map[string]string{
						"message": "%s",
					},
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-%d", time.Now().Unix()),
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
		"name":        fmt.Sprintf("bedrock-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Bedrock Guardrail Test Service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/post",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second) // Wait for propagation

	testCases := []struct {
		name       string
		input      string
		expectCode int
	}{
		// {"Safe Content", "The latest deployment includes performance improvements and bug fixes.", http.StatusOK},
		// {"Policy Violation", "I hate the negro obama", http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := []byte(tc.input)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "text/plain")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
