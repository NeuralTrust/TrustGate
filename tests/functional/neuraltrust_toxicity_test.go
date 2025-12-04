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

func TestNeuralTrustToxicityPlugin(t *testing.T) {
	subdomain := fmt.Sprintf("neuraltrust-toxicity-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "NeuralTrust Toxicity Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "neuraltrust_toxicity",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"toxicity": map[string]interface{}{
						"enabled":   true,
						"threshold": 0.5,
					},
					"credentials": map[string]interface{}{
						"neuraltrust": map[string]string{
							"token":    os.Getenv("NEURAL_TRUST_FIREWALL_API_KEY"),
							"base_url": os.Getenv("NEURAL_TRUST_FIREWALL_URL"),
						},
					},
					"mapping_field": "input.text",
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
		"name":        fmt.Sprintf("neuraltrust-toxicity-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "NeuralTrust Toxicity Test Service",
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
		{
			"Safe Content",
			"{\"input\": {\"text\": \"I like Cats\"}}",
			http.StatusOK,
		},
		{
			"Toxicity Violation",
			"{\"input\": {\"text\": \"I Hate obama negro president\"}}",
			http.StatusForbidden,
		},
		{
			"Toxicity Violation - Direct Text",
			"I Hate obama negro president",
			http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := []byte(tc.input)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}

func TestNeuralTrustToxicityPlugin_WithOpenAI(t *testing.T) {
	subdomain := fmt.Sprintf("neuraltrust-toxicity-openai-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "NeuralTrust Toxicity Gateway with OpenAI",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "neuraltrust_toxicity",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"provider": "openai",
					"toxicity": map[string]interface{}{
						"enabled":   true,
						"threshold": 0.5,
					},
					"credentials": map[string]interface{}{
						"openai": map[string]string{
							"api_key": os.Getenv("OPENAI_API_KEY"),
						},
					},
					"mapping_field": "input.text",
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
		"name":        fmt.Sprintf("neuraltrust-toxicity-openai-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "NeuralTrust Toxicity Test Service with OpenAI",
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
		{
			"Safe Content",
			"{\"input\": {\"text\": \"I like Cats\"}}",
			http.StatusOK,
		},
		{
			"Toxicity Violation",
			"{\"input\": {\"text\": \"I Hate obama negro president\"}}",
			http.StatusForbidden,
		},
		{
			"Toxicity Violation - Direct Text",
			"I Hate obama negro president",
			http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := []byte(tc.input)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
